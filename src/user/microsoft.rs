/*
 * Epilyon, keeping EPITA students organized
 * Copyright (C) 2019-2020 Adrien 'Litarvan' Navratil
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
use std::collections::HashMap;

use serde::{Serialize, Deserialize};
use serde_json::json;
use chrono::{DateTime, Utc, TimeZone};
use failure::Fail;
use time::Duration;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};

use crate::config::CONFIG;
use crate::http::jwt;

#[derive(Clone, Serialize, Deserialize)]
pub struct MSUser {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: DateTime<Utc>
}

#[derive(Clone, Serialize, Deserialize)]
pub struct MSSubscription {
    pub id: String,
    pub expires_at: DateTime<Utc>
}

pub fn get_redirect_uri(state: &str, nonce: &str) -> String {
    let scopes: String = CONFIG.ms_scopes.join("+");

    format!(
        "{}/oauth2/v2.0/authorize?response_type=code&response_mode=form_post&redirect_uri={}&client_id={}&scope={}&prompt=select_account&state={}&nonce={}",
        CONFIG.ms_tenant_url,
        utf8_percent_encode(CONFIG.ms_redirect_uri.clone(), NON_ALPHANUMERIC).to_string(),
        &CONFIG.ms_client_id,
        scopes,
        state,
        nonce
    )
}

pub async fn identify(code: &str, nonce: &str) -> Result<(String, MSUser), MSError> {
    let client = reqwest::Client::new();
    let mut params = HashMap::new();

    let scopes: String = CONFIG.ms_scopes.join(" ");

    params.insert("client_info", "1");
    params.insert("code", &code);
    params.insert("client_id", &CONFIG.ms_client_id);
    params.insert("client_secret", &CONFIG.ms_secret);
    params.insert("redirect_uri", &CONFIG.ms_redirect_uri);
    params.insert("scope", &scopes);
    params.insert("grant_type", "authorization_code");

    let res = client.post(&format!("{}/oauth2/v2.0/token", CONFIG.ms_tenant_url))
        .form(&params)
        .send().await?
        .json::<AuthorizationResult>().await?;

    let access_token: TokenContent = jwt::decode(&res.access_token)?;
    let id_token: IdTokenContent = jwt::decode(&res.id_token)?;

    if id_token.aud != CONFIG.ms_client_id {
        return Err(MSError::InvalidAudience);
    }

    if id_token.nonce != nonce {
        return Err(MSError::InvalidNonce);
    }

    Ok((access_token.unique_name.clone(), MSUser {
        access_token: res.access_token.clone(),
        refresh_token: res.refresh_token.clone(),
        expires_at: Utc.timestamp(access_token.exp as i64, 0)
    }))
}

pub async fn refresh(user: &MSUser) -> Result<MSUser, MSError> {
    let client = reqwest::Client::new();
    let mut params = HashMap::new();

    let scopes: String = CONFIG.ms_scopes.join(" ");

    params.insert("client_info", "1");
    params.insert("refresh_token", &user.refresh_token);
    params.insert("client_id", &CONFIG.ms_client_id);
    params.insert("client_secret", &CONFIG.ms_secret);
    params.insert("scope", &scopes);
    params.insert("grant_type", "refresh_token");

    let res = client.post(&format!("{}/oauth2/v2.0/token", CONFIG.ms_tenant_url))
        .form(&params)
        .send().await?
        .json::<RefreshResult>().await?;

    let access_token: TokenContent = jwt::decode(&res.access_token)?;

    Ok(MSUser {
        access_token: res.access_token.clone(),
        refresh_token: res.refresh_token.clone(),
        expires_at: Utc.timestamp(access_token.exp as i64, 0)
    })
}

pub async fn get_mails(user: &MSUser, filter: &str, count: usize) -> Result<Vec<Mail>, MSError> {
    let url = format!(
        "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages?\
            $select=id,receivedDateTime,hasAttachments,subject,sender&\
            $orderby=receivedDateTime desc&\
            $filter={}&\
            $top={}",
        filter,
        count
    );

    ms_request::<Vec<Mail>>(user, &url).await
}

pub async fn get_first_attachment(user: &MSUser, mail: &Mail, filter: &str) -> Result<Option<Attachment>, MSError> {
    let url = format!(
        "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages/{}/attachments?$filter={}",
        &mail.id,
        filter
    );

    let mut result = ms_request::<Vec<Attachment>>(user, &url).await?;
    if result.len() > 0 {
        Ok(Some(result.swap_remove(0)))
    } else {
        Ok(None)
    }
}

pub async fn subscribe(user: &MSUser, resource: &str) -> Result<SubscriptionResponse, MSError> {
    // TODO: Don't do it on localhost

    Ok(reqwest::Client::new().post("https://graph.microsoft.com/v1.0/subscriptions")
        .header("Authorization", format!("Bearer {}", user.access_token))
        .json(&json!({
            "changeType": "created,updated",
            "notificationUrl": &CONFIG.ms_webhook_uri,
            "resource": resource,
            "expirationDateTime": Utc::now() + Duration::days(2),
            "clientState": &CONFIG.ms_webhook_key
        }))
        .send().await?
        .json::<SubscriptionResponse>().await?)
}

pub async fn unsubscribe(user: &MSUser, id: &str) -> Result<(), MSError> {
    Ok(reqwest::Client::new().delete(format!("https://graph.microsoft.com/v1.0/subscriptions/{}", id))
        .header("Authorization", format!("Bearer {}", user.access_token))
        .send().await?)
}

async fn ms_request<T>(user: &MSUser, url: &str) -> Result<T, MSError>
    where T:  serde::de::DeserializeOwned
{
    Ok(reqwest::Client::new().get(url)
        .header("Authorization", format!("Bearer {}", user.access_token))
        .send().await?
        .json::<MSResponse<T>>().await?
        .value)
}

#[derive(Deserialize)]
struct AuthorizationResult {
    access_token: String,
    refresh_token: String,
    id_token: String
}

#[derive(Deserialize)]
struct TokenContent {
    pub exp: usize,
    pub unique_name: String
}

#[derive(Deserialize)]
struct IdTokenContent {
    pub aud: String,
    pub nonce: String
}

#[derive(Deserialize)]
struct RefreshResult {
    #[allow(dead_code)]
    expires_in: usize,
    access_token: String,
    refresh_token: String
}

#[derive(Deserialize)]
pub struct MSResponse<T> {
    pub value: T
}

#[allow(non_snake_case)] // This is from a JSON, we can't change that
#[derive(Deserialize)]
pub struct Mail {
    pub id: String,
    pub receivedDateTime: DateTime<Utc>,
    pub hasAttachments: bool,
    pub subject: String,
    pub sender: MailSender
}

#[allow(non_snake_case)]
#[derive(Deserialize)]
pub struct MailSender {
    pub emailAddress: MailAddress
}

#[derive(Deserialize)]
pub struct MailAddress {
    pub name: String,
    pub address: String
}

#[allow(non_snake_case)] // This is from a JSON, we can't change that
#[derive(Clone, Deserialize)]
pub struct Attachment {
    pub name: String,
    pub contentBytes: String
}

#[allow(non_snake_case)] // This is from a JSON, we can't change that
#[derive(Deserialize)]
pub struct SubscriptionResponse {
    pub id: String,
    pub expirationDateTime: DateTime<Utc>
}

#[allow(non_snake_case)] // This is from a JSON, we can't change that
#[derive(Clone, Deserialize)]
pub struct Notification {
    pub subscriptionId: String,
    pub subscriptionExpirationDateTime: DateTime<Utc>,
    pub clientState: String,
    pub changeType: String
}

#[derive(Fail, Debug)]
pub enum MSError {
    #[fail(display = "Remote MS server error / unexcepted response : {}. \
    This is bad : please contact the devs", error)]
    RemoteError {
        error: reqwest::Error
    },

    #[fail(display = "Invalid token received from MS : {}. \
    This is bad : please contact the devs", error)]
    RemoteTokenError {
        error: jwt::JwtParsingError
    },

    #[fail(display = "Failed to decode MS response content : {}", error)]
    ContentDecodingError {
        error: base64::DecodeError
    },

    #[fail(display = "Given token was issued by another application")]
    InvalidAudience,

    #[fail(display = "Invalid nonce token, probable CSRF or similar attack")]
    InvalidNonce
}

from_error!(reqwest::Error, MSError, MSError::RemoteError);
from_error!(jwt::JwtParsingError, MSError, MSError::RemoteTokenError);
