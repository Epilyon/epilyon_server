use std::env;

use serde::{Deserialize, de::DeserializeOwned};

use crate::users::{User, UserManager};
use crate::error::{EpiResult, EpiError};

// TODO: Cache CRI users in case of the CRI being down

pub fn load_users(users: &mut UserManager) -> EpiResult<()> {
    let client = CRIClient::new()?;

    for promo in client.vars.promos.iter() {
        load_promo(&client, promo, users)?;
    }

    Ok(())
}

fn load_promo(client: &CRIClient, promo: &str, users: &mut UserManager) -> EpiResult<()> {
    let result: reqwest::Result<UsersListResponse> = client.request(&format!("/api/users/?limit=2000&promo={}", promo)); // A bit dirty, but fast

    match result {
        Ok(response) => {
            for remote in response.results {
                let mut region = get_region(&remote);

                if region.is_none() {
                    warn!("Can't find region for user '{}', using Paris", remote.login);
                    region = Some("Paris".into());
                }

                users.users.push(User {
                    uid: remote.uidNumber,
                    first_name: remote.firstname,
                    last_name: remote.lastname,
                    email: remote.mail,
                    promo: remote.promo,
                    region: region.unwrap(),
                    groups: Vec::new() // TODO: Load user groups from database
                });
            }

            Ok(())
        },
        Err(e) => {
            error!("CRI API threw an error during list request for promo '{}' : {}", promo, e);
            Err(EpiError::RemoteError)
        }
    }
}

fn get_region(user: &UserResponse) -> Option<String> {
    let mut result = None;

    for s in user.class_groups.iter() {
        if s.starts_with(&user.promo) {
            let split: Vec<&str> = s.split("_").collect();

            if let Some(region) = split.get(2) {
                result = Some(capitalize(region))
            }
        }
    }

    result
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();

    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
    }
}

#[derive(Deserialize)]
struct UsersListResponse {
    count: usize,
    results: Vec<UserResponse>
}

#[allow(non_snake_case)] // This is from a JSON, we can't change that
#[derive(Deserialize)]
struct UserResponse {
    login: String,
    uidNumber: usize,
    mail: String,
    lastname: String,
    firstname: String,
    promo: String,
    class_groups: Vec<String>,
    photo: String,
    url: String
}

struct CRIClient {
    vars: CRIEnvVars,
    http: reqwest::Client
}

impl CRIClient {
    fn new() -> EpiResult<Self> {
        Ok(CRIClient {
            vars: CRIEnvVars::get_result()?,
            http: reqwest::Client::new()
        })
    }

    fn request<T: DeserializeOwned>(&self, uri: &str) -> reqwest::Result<T> {
        let url = self.vars.url.clone() + uri;

        self.http.get(&url)
            .header("Accept", "application/json")
            .basic_auth(&self.vars.accessor_username, Some(&self.vars.accessor_password)) // CRI API requires an user to peform the requests
            .send()
            .and_then(|mut r| r.json())
    }
}

struct CRIEnvVars {
    url: String,
    accessor_username: String,
    accessor_password: String,
    promos: Vec<String>
}

impl CRIEnvVars {
    fn get() -> Option<CRIEnvVars> {
        Some(CRIEnvVars {
            url: env::var("CRI_URL").ok()?,
            accessor_username: env::var("CRI_ACCESSOR_USERNAME").ok()?, // .ok() turns Result into Option to makes us able to use ?'
            accessor_password: env::var("CRI_ACCESSOR_PASSWORD").ok()?,
            promos: env::var("CRI_PROMOS").ok()?.split(",").map(|s| s.into()).collect()
        })
    }

    fn get_result() -> EpiResult<CRIEnvVars> {
        match Self::get() {
            Some(vars) => Ok(vars),
            None => Err(EpiError::MissingVar)
        }
    }
}
