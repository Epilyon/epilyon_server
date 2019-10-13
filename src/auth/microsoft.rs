use std::collections::HashMap;
use std::env;

use rocket::http::uri::Uri;
use serde::Deserialize;

use crate::auth::{AuthError, AuthIdentity};
use crate::http::jwt;

type AuthResult<T> = std::result::Result<T, AuthError>;

pub fn get_redirect_uri(state: &str, nonce: &str) -> AuthResult<String> {
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

pub fn acquire_token(code: &str) -> AuthResult<AuthIdentity> {
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
                    let jwt: Result<TokenContent, jwt::ParsingError> = jwt::decode(&json.access_token);

                    match jwt {
                        Ok(content) => Ok(AuthIdentity::new(
                            content.name,
                            content.unique_name,
                            json.access_token,
                            json.refresh_token
                        )),
                        Err(e) => {
                            println!("JWT Parsing error : '{}'", e); // TODO: Logger
                            Err(AuthError::RemoteError)
                        }
                    }
                },
                Err(e) => {
                    println!("JSON Parsing error : '{}'", e); // TODO: Logger
                    Err(AuthError::RemoteError)
                }
            }
        },
        Err(e) => {
            println!("HTTP Request error : '{}'", e); // TODO: Logger
            Err(AuthError::RemoteError)
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

    fn get_result() -> AuthResult<MSEnvVars> {
        match Self::get() {
            Some(vars) => Ok(vars),
            None => Err(AuthError::MissingMSVars)
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

/*let vars = vec![
            "MS_TENANT_URL", "MS_CLIENT_ID", "MS_CLIENT_SECRET", "MS_REDIRECT_URI", "MS_SCOPES"
        ];

        let mut result = vec![];

        for name in vars.iter() {
            match std::env::var(name) {
                Some(var) => result.push(var),
                None => {
                    return None;
                }
            }
        }

        return Some(MSEnvVars {
            tenant_url: result.get(0).unwrap(),
            client_id: result.get(1).unwrap(),
            client_secret: result.get(2).unwrap(),
            scopes: result.get(3)?
        })*/