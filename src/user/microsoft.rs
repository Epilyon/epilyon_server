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
use serde_json::{json, Value};
use chrono::{DateTime, Utc, TimeZone};
use failure::Fail;
use time::Duration;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use reqwest::{Method as HttpMethod, Client as HttpClient, Error as HttpError};

use crate::config::CONFIG;
use crate::http::jwt;

type MSResult<T> = Result<T, MSError>;

#[derive(Clone, Serialize, Deserialize)]
pub struct MSUser {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: DateTime<Utc>
}

#[derive(Clone, Serialize, Deserialize)]
pub struct MSSubscription {
    pub _key: String,
    pub id: String,
    pub expires_at: DateTime<Utc>
}

pub fn get_redirect_uri(state: &str, nonce: &str) -> String {
    let scopes: String = CONFIG.ms_scopes.join("+");

    format!(
        "{}/oauth2/v2.0/authorize?response_type=code&response_mode=form_post&redirect_uri={}&client_id={}&scope={}&prompt=select_account&state={}&nonce={}",
        CONFIG.ms_tenant_url,
        utf8_percent_encode(&CONFIG.ms_redirect_uri.clone(), NON_ALPHANUMERIC).to_string(),
        &CONFIG.ms_client_id,
        scopes,
        state,
        nonce
    )
}

pub async fn identify(code: &str, nonce: &str) -> MSResult<(String, MSUser)> {
    let mut params = HashMap::new();
    let scopes: String = CONFIG.ms_scopes.join(" ");

    params.insert("client_info", "1");
    params.insert("code", &code);
    params.insert("client_id", &CONFIG.ms_client_id);
    params.insert("client_secret", &CONFIG.ms_secret);
    params.insert("redirect_uri", &CONFIG.ms_redirect_uri);
    params.insert("scope", &scopes);
    params.insert("grant_type", "authorization_code");

    let res = fetch_json_with_form::<AuthorizationResult>(
        &format!("{}/oauth2/v2.0/token", CONFIG.ms_tenant_url),
        params
    ).await?;

    let access_token: TokenContent = jwt::decode(&res.access_token)
        .map_err(|e| MSError::RemoteTokenError {
            token: res.access_token.clone(),
            error: e
        })?;
    let id_token: IdTokenContent = jwt::decode(&res.id_token)
        .map_err(|e| MSError::RemoteTokenError {
            token: res.id_token.clone(),
            error: e
        })?;

    if id_token.aud != CONFIG.ms_client_id {
        return Err(MSError::InvalidAudience {
            audience: id_token.aud.clone()
        });
    }

    if id_token.nonce != nonce {
        return Err(MSError::InvalidNonce {
            nonce: id_token.nonce.clone()
        });
    }

    Ok((access_token.unique_name.clone(), MSUser {
        access_token: res.access_token.clone(),
        refresh_token: res.refresh_token.clone(),
        expires_at: Utc.timestamp(access_token.exp as i64, 0)
    }))
}

pub async fn refresh(user: &MSUser) -> MSResult<MSUser> {
    let mut params = HashMap::new();
    let scopes: String = CONFIG.ms_scopes.join(" ");

    params.insert("client_info", "1");
    params.insert("refresh_token", &user.refresh_token);
    params.insert("client_id", &CONFIG.ms_client_id);
    params.insert("client_secret", &CONFIG.ms_secret);
    params.insert("scope", &scopes);
    params.insert("grant_type", "refresh_token");

    let res = fetch_json_with_form::<RefreshResult>(
        &format!("{}/oauth2/v2.0/token", CONFIG.ms_tenant_url),
        params
    ).await?;

    let access_token: TokenContent = jwt::decode(&res.access_token)
        .map_err(|e| MSError::RemoteTokenError {
            token: res.access_token.clone(),
            error: e
        })?;

    Ok(MSUser {
        access_token: res.access_token.clone(),
        refresh_token: res.refresh_token.clone(),
        expires_at: Utc.timestamp(access_token.exp as i64, 0)
    })
}

pub async fn get_mails(user: &MSUser, filter: &str, count: usize) -> MSResult<Vec<Mail>> {
    let url = format!(
        "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages?\
            $select=id,receivedDateTime,hasAttachments,subject,sender&\
            $orderby=receivedDateTime desc&\
            $filter={}&\
            $top={}",
        filter,
        count
    );

    Ok(fetch_graph::<MSValue<Vec<Mail>>>(user, HttpMethod::GET, &url, None).await?.value)
}

pub async fn get_first_attachment(user: &MSUser, mail: &Mail, filter: &str) -> MSResult<Option<Attachment>> {
    let url = format!(
        "/me/mailFolders/inbox/messages/{}/attachments?$filter={}",
        &mail.id,
        filter
    );

    let mut result = fetch_graph::<MSValue<Vec<Attachment>>>(
        user,
        HttpMethod::GET,
        &url,
        None
    ).await?.value;

    if result.len() > 0 {
        Ok(Some(result.swap_remove(0)))
    } else {
        Ok(None)
    }
}

pub async fn subscribe(user: &MSUser, resource: &str) -> MSResult<SubscriptionResponse> {
    // TODO: Don't do it on localhost

    fetch_graph(
        user,
        HttpMethod::POST,
        "/subscriptions",
        Some(json!({
            "changeType": "created,updated",
            "notificationUrl": &CONFIG.ms_webhook_uri,
            "resource": resource,
            "expirationDateTime": Utc::now() + Duration::days(2),
            "clientState": &CONFIG.ms_webhook_key
        }))
    ).await
}

pub async fn renew_subscription(user: &MSUser, id: &str) -> MSResult<DateTime<Utc>> {
    let time = Utc::now() + Duration::days(2);

    call_graph(
        user,
        HttpMethod::PATCH,
        &format!("/subscriptions/{}", id),
        Some(json!({
            "expirationDateTime": time
        })),
    ).await?;

    Ok(time)
}

pub async fn unsubscribe(user: &MSUser, id: &str) -> MSResult<()> {
    call_graph(
        user,
        HttpMethod::DELETE,
        &format!("/subscriptions/{}", id),
        None,
    ).await
}

async fn call_graph(
    user: &MSUser,
    method: HttpMethod,
    url: &str,
    content: Option<Value>,
) -> MSResult<()> {
    let mut builder = HttpClient::new()
        .request(method, url)
        .header("Authorization", &format!("Bearer {}", user.access_token));

    if let Some(cont) = content {
        builder = builder.json(&cont);
    }

    builder.send().await?;

    Ok(())
}

async fn fetch_graph<T>(
    user: &MSUser,
    method: HttpMethod,
    url: &str,
    content: Option<Value>
) -> MSResult<T>
    where T: serde::de::DeserializeOwned
{
    let mut builder = HttpClient::new()
        .request(method, &format!("https://graph.microsoft.com/v1.0{}", url));

    if let Some(cont) = content {
        builder = builder.json(&cont);
    }

    fetch_json(builder, Some(&user.access_token)).await
}

async fn fetch_json_with_form<T>(url: &str, content: HashMap<&str, &str>) -> MSResult<T>
    where T: serde::de::DeserializeOwned
{
    let req = HttpClient::new()
        .post(url)
        .form(&content);

    fetch_json(req, None).await
        .map_err(|e| match e {
            MSError::RemoteError { method, url, request: _, response, error } => MSError::RemoteError {
                method,
                url,
                request: serde_json::to_string_pretty(&content).unwrap_or("".to_string()),
                response,
                error
            },
            e => e
        })
}

async fn fetch_json<T>(mut builder: reqwest::RequestBuilder, token: Option<&str>) -> MSResult<T>
    where T: serde::de::DeserializeOwned
{
    if let Some(tok) = token {
        builder = builder.header("Authorization", format!("Bearer {}", tok));
    }

    let request = builder.build()?;
    let method = format!("{}", request.method());
    let url = format!("{}", request.url());
    let response: String = HttpClient::new()
        .execute(request).await?
        .text().await?;

    serde_json::from_str(&response)
        .map_err(move |e| MSError::RemoteError {
            method,
            url,
            request: String::new(),
            response,
            error: e
        })
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
pub struct MSValue<T> {
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
    #[fail(display = "HTTP error during request")]
    HttpError {
        error: HttpError
    },

    #[fail(display = "Microsoft request was rejected")]
    RemoteError {
        method: String,
        url: String,
        request: String,
        response: String,
        error: serde_json::Error
    },

    #[fail(display = "Invalid token received from Microsoft")]
    RemoteTokenError {
        token: String,
        error: jwt::JwtParsingError
    },

    #[fail(display = "Failed to decode mail attachment")]
    ContentDecodingError {
        error: base64::DecodeError
    },

    #[fail(display = "Given token was issued by another application")]
    InvalidAudience {
        audience: String
    },

    #[fail(display = "Invalid nonce token (probable CSRF or similar attack)")]
    InvalidNonce {
        nonce: String
    }
}

impl MSError {
    pub fn to_detailed_string(&self) -> String {
        use MSError::*;

        let mut result = String::new();
        result += &self.to_string();

        match self {
            HttpError { error } => {
                result += &format!(", reqwest dropped error '{}'", error);
            },
            RemoteError { method, url, request, response, error } => {
                result += &format!(
                    "\nRequest : {} {}\nSerde error : {}\nRequest : ",
                    method,
                    url,
                    error
                );

                if request.is_empty() {
                    result += "(empty)\n";
                } else {
                    result += &format!("\n{}\n---------\n", request);
                }

                let res = serde_json::from_str::<Value>(response)
                    .and_then(|v| serde_json::to_string_pretty(&v));

                let pretty_response = match res.as_ref() {
                    Ok(json) => json,
                    _ => response
                };

                result += &format!("Response :\n{}", pretty_response);
            },
            RemoteTokenError { token, error} => {
                result += &format!(", error is '{}' and token was :\n{}", error, token)
            },
            ContentDecodingError { error } => {
                result += &format!(", base64 dropped error '{}", error);
            },
            InvalidAudience { audience } => {
                result += &format!(" : {}", audience);
            },
            InvalidNonce { nonce } => {
                result += &format!(" : {}", nonce);
            }
        }

        result
    }
}

from_error!(reqwest::Error, MSError, MSError::HttpError);
