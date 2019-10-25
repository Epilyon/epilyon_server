use std::collections::HashMap;
use std::env;

use rocket::http::uri::Uri;
use serde::Deserialize;
use chrono::{DateTime, Utc};

use crate::users::auth::{AuthIdentity, AuthSession};
use crate::users::UserManager;
use crate::error::{EpiResult, EpiError};

pub fn get_redirect_uri(state: &str, nonce: &str) -> EpiResult<String> {
    MSEnvVars::get_result().map(|vars| format!(
        "{}/oauth2/v2.0/authorize?response_type=code&response_mode=form_post&redirect_uri={}&client_id={}&scope={}&prompt=select_account&state={}&nonce={}",
        &vars.tenant_url,
        Uri::percent_encode(&vars.redirect_uri),
        &vars.client_id,
        &vars.scopes,
        state,
        nonce
    ))
}

pub fn identify(session: &mut AuthSession, users: &UserManager, code: &str) -> EpiResult<()> {
    let vars = MSEnvVars::get_result()?;

    let client = reqwest::Client::new();
    let mut params = HashMap::new();

    let scopes = vars.scopes.replace("+", " "); // Need to be declared here to make it live the whole function

    params.insert("client_info", "1");
    params.insert("code", code);
    params.insert("client_id", &vars.client_id);
    params.insert("client_secret", &vars.client_secret);
    params.insert("redirect_uri", &vars.redirect_uri);
    params.insert("scope", &scopes);
    params.insert("grant_type", "authorization_code");

    let res = client.post(&format!("{}/oauth2/v2.0/token", &vars.tenant_url))
        .form(&params)
        .send();

    match res {
        Ok(mut r) => {
            let auth_result: Result<AuthorizationResult, reqwest::Error> = r.json();

            match auth_result {
                Ok(json) => {
                    let jwt = jwt::dangerous_unsafe_decode::<TokenContent>(&json.access_token);
                    let id_jwt = jwt::dangerous_unsafe_decode::<IdTokenContent>(&json.id_token);

                    match jwt {
                        Ok(content) => match id_jwt {
                            Ok(id_content) => {
                                if id_content.claims.aud != vars.client_id {
                                    error!("Client ID does not match id_token audience : '{}' != '{}'", &id_content.claims.aud, &vars.client_id);
                                    return Err(EpiError::RemoteError);
                                }

                                if id_content.claims.nonce != session.nonce() {
                                    error!("Nonce do not match : '{}' != '{}'", &id_content.claims.nonce, session.nonce());
                                    return Err(EpiError::RemoteError);
                                }

                                // TODO: Check expiration of given tokens

                                session.identify(
                                    users,
                                    &content.claims.unique_name,
                                    json.access_token.clone(),
                                    json.refresh_token.clone(),
                                    json.expires_in
                                )
                            },
                            Err(e) => {
                                error!("Failed to parse id_token JWT '{}' : {}", &json.id_token, e);
                                Err(EpiError::RemoteError)
                            }
                        },
                        Err(e) => {
                            error!("Failed to parse access_token JWT '{}' : {}", &json.access_token, e);
                            Err(EpiError::RemoteError)
                        }
                    }
                },
                Err(e) => {
                    error!("Failed to parse response JSON : {}", e);
                    Err(EpiError::RemoteError)
                }
            }
        },
        Err(e) => {
            error!("Failed to execute OAuth token request : {}", e);
            Err(EpiError::RemoteError)
        }
    }
}

pub fn get_mails(identity: &AuthIdentity) -> EpiResult<Vec<Mail>> {
    let client = reqwest::Client::new();

    let res = client.post("https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages")
        .header("Authorization", format!("Bearer {}", identity.access_token()))
        .send();

    match res {
        Ok(mut response) => {
            let json: Result<MSResponse<Vec<Mail>>, reqwest::Error> = response.json();

            match json {
                Ok(content) => Ok(content.value),
                Err(e) => {
                    error!("Error while during deserialization of mail listing request response from Microsoft : {}", e);
                    Err(EpiError::RemoteError)
                }
            }
        },
        Err(e) => {
            error!("Error while sending mail listing request to Microsoft : {}", e);
            Err(EpiError::RemoteError)
        }
    }
}

struct MSEnvVars {
    tenant_url: String,
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    scopes: String,
}

impl MSEnvVars {
    fn get() -> Option<MSEnvVars> {
        Some(MSEnvVars {
            tenant_url: env::var("MS_TENANT_URL").ok()?, // .ok() turns Result into Option to makes us able to use ?'
            client_id: env::var("MS_CLIENT_ID").ok()?,
            client_secret: env::var("MS_CLIENT_SECRET").ok()?,
            redirect_uri: env::var("MS_REDIRECT_URI").ok()?,
            scopes: env::var("MS_SCOPES").ok()?
        })
    }

    fn get_result() -> EpiResult<MSEnvVars> {
        match Self::get() {
            Some(vars) => Ok(vars),
            None => Err(EpiError::MissingVar)
        }
    }
}

#[derive(Deserialize)]
struct AuthorizationResult {
    expires_in: usize,
    access_token: String,
    refresh_token: String,
    id_token: String
}

#[derive(Deserialize)]
struct TokenContent {
    pub name: String,
    pub unique_name: String
}

#[derive(Deserialize)]
struct IdTokenContent {
    pub aud: String,
    pub nonce: String
}

#[derive(Deserialize)]
struct MSResponse<T> {
    value: T
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