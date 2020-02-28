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
use serde::{Serialize, Deserialize};
use serde_json::Value;
use failure::Fail;
use log::{info, warn};

#[derive(Serialize, Deserialize, Clone)]
pub struct CRIUser {
    pub username: String,
    pub first_name: String,
    pub last_name: String,
    pub email: String,
    pub promo: String,
    pub avatar: String
}

pub async fn fetch_users(cri_url: &str, username: &str, password: &str, promos: &Vec<String>) -> Result<Vec<(u32, CRIUser)>, CRIError> {
    info!("Fetching users from CRI...");

    let http = reqwest::Client::new();

    let mut users: Vec<(u32, CRIUser)> = Vec::new();
    let mut count: usize = 0;

    for promo in promos {
        let res = http.get(&format!("{}/api/users/?limit=2000&promo={}", cri_url, promo))
            .header("Accept", "application/json")
            .basic_auth(username, Some(password))
            .send().await?
            .text().await?;

        let json: Value = serde_json::from_str(&res)
            .map_err(|e| CRIError::RemoteError { error: e, response: res.clone() })?;

        let response: Vec<UserResponse> = serde_json::from_value(json["results"].clone())
            .map_err(|e| CRIError::RemoteError { error: e, response: res.clone() })?;

        count += response.len();

        for u in response {
            match get_region(&u) {
                Some(r) => {
                    if r == "lyon" {
                        users.push((u.uidNumber as u32, CRIUser {
                            username: u.login.clone(),
                            first_name: capitalize(&u.firstname),
                            last_name: capitalize(&u.lastname),
                            email: u.mail.clone(),
                            promo: u.promo.clone(),
                            avatar: u.photo.clone()
                        }));
                    }
                },
                None => {
                    warn!("Unknown region for user '{} {}', skipping...", u.firstname, u.lastname);
                }
            }

        }
    }

    info!("Filtered {} users from CRI out of {} fetched, from promos {:?}", users.len(), count, promos);

    Ok(users)
}

fn get_region(user: &UserResponse) -> Option<String> {
    let mut result = None;

    for s in user.class_groups.iter() {
        if s.starts_with(&user.promo) {
            let split: Vec<&str> = s.split("_").collect();

            if let Some(region) = split.get(2) {
                result = Some(region.to_lowercase())
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
    photo: String
}

#[derive(Debug, Fail)]
pub enum CRIError {
    #[fail(display = "HTTP error while requesting CRI")]
    HttpError {
        error: reqwest::Error
    },

    #[fail(display = "CRI API threw an error or an unknown response format")]
    RemoteError {
        error: serde_json::Error,
        response: String
    }
}

impl CRIError {
    pub fn to_detailed_string(&self) -> String {
        use CRIError::*;

        let mut result = String::new();
        result += &self.to_string();

        match self {
            HttpError { error } => {
                result += &format!(", reqwest dropped error '{}'", error);
            },
            RemoteError { response, error } => {
                result += &format!(". Serde dropped error '{}' while parsing response :\n{}", error, response);
            },
        }

        result
    }
}

from_error!(reqwest::Error, CRIError, CRIError::HttpError);
