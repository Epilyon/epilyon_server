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
use log::info;
use crate::CONFIG;

#[derive(Serialize, Deserialize, Clone)]
pub struct CRIUser {
    pub username: String,
    pub first_name: String,
    pub last_name: String,
    pub email: String,
    pub promo: String,
    pub avatar: String,
}


pub async fn fetch_user(email: &str) -> Result<(u32, CRIUser), CRIError> {
    info!("Looking for user with email '{}' on the CRI", email);

    let http = reqwest::Client::new();
    let res = http.get(&format!("{}/api/v2/users/search?emails={}", CONFIG.cri_url, email))
        .header("Accept", "application/json")
        .basic_auth(&CONFIG.cri_accessor_username, Some(&CONFIG.cri_accessor_password))
        .send().await?
        .text().await?;

    let value: Value = serde_json::from_str(&res)
        .map_err(|e| CRIError::RemoteError { error: e, response: res.clone() })?;
    let pretty: String = serde_json::to_string_pretty(&value)
        .map_err(|e| CRIError::RemoteError { error: e, response: res.clone() })?;
    let response: SearchResponse = serde_json::from_str(&pretty)
        .map_err(|e| CRIError::RemoteError { error: e, response: pretty.clone() })?;

    let user = response.results.get(0)
        .ok_or_else(|| CRIError::NoMatch { email: email.to_string() })?;

    let group = user.groups_history.iter().find(|g| g.is_current)
        .ok_or_else(|| CRIError::NoPromo { email: email.to_string() })?;

    info!("Found user '{}' from promo '{}'", user.login, group.graduation_year);

    Ok((user.uid, CRIUser {
        username: user.login.clone(),
        first_name: capitalize(&user.first_name),
        last_name: capitalize(&user.last_name),
        email: user.email.clone(),
        promo: group.graduation_year.to_string(),
        avatar: format!("{}/{}", CONFIG.cri_photos_url, user.login),
    }))
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();

    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
    }
}

#[derive(Deserialize)]
struct SearchResponse {
    results: Vec<UserResponse>
}

#[derive(Deserialize)]
struct UserResponse {
    login: String,
    uid: u32,
    first_name: String,
    last_name: String,
    email: String,
    groups_history: Vec<UserGroup>
}

#[derive(Deserialize)]
struct UserGroup {
    graduation_year: u16,
    is_current: bool
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
        response: String,
    },

    #[fail(display = "Can't find user with email '{}' on the CRI", email)]
    NoMatch {
        email: String
    },

    #[fail(display = "User with email '{}' has no current group, can't find their promotion", email)]
    NoPromo {
        email: String
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
            }
            RemoteError { response, error } => {
                result += &format!(". Serde dropped error '{}' while parsing response :\n{}", error, response);
            }
            NoMatch { .. } => {}
            NoPromo { .. } => {}
        }

        result
    }
}

from_error!(reqwest::Error, CRIError, CRIError::HttpError);
