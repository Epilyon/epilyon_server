use std::fmt;
use std::error::Error;
use std::env;

use serde::{Deserialize, de::DeserializeOwned};

use crate::users::{User, UserManager};

type CRIResult<T> = std::result::Result<T, CRIError>;

pub fn load_users() -> CRIResult<UserManager> {
    let client = CRIClient::new()?;
    let mut users = UserManager::new();

    for promo in client.vars.promos.iter() {
        load_promo(&client, promo, &mut users)?;
    }

    Ok(users)
}

fn load_promo(client: &CRIClient, promo: &str, users: &mut UserManager) -> CRIResult<()> {
    let result: reqwest::Result<UsersListResponse> = client.request(&format!("/api/users/?limit=2000&promo={}", promo)); // A bit dirty, but fast

    match result {
        Ok(response) => {
            for remote in response.results {
                let mut region = get_region(&remote);

                if region.is_none() {
                    warn!("Can't find region for user '{}', setting Paris", remote.login);
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
            Err(CRIError::RemoteError)
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
    next: Option<String>,
    previous: Option<String>,
    results: Vec<UserResponse>
}

#[allow(non_snake_case)] // This is from a JSON, we can't change that
#[derive(Deserialize)]
struct UserResponse {
    login: String,
    uidNumber: usize,
    gidNumber: usize,
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
    fn new() -> CRIResult<Self> {
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

    fn get_result() -> CRIResult<CRIEnvVars> {
        match Self::get() {
            Some(vars) => Ok(vars),
            None => Err(CRIError::MissingVars)
        }
    }
}

#[derive(Debug)]
pub enum CRIError {
    MissingVars,
    RemoteError
}

impl fmt::Display for CRIError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use CRIError::*;

        // TODO: Lang? Client-side?
        write!(f, "{}", match self {
            MissingVars => "Server setup error : Missing one of the CRI .env var (did you copy the .env.example to .env ?)",
            RemoteError => "CRI API threw an error or a malformed response, this is bad : report this to the devs",
        })
    }
}

impl Error for CRIError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}