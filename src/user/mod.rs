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
use failure::Fail;
use serde::{Serialize, Deserialize};
use serde_json::json;
use log::{info, warn};
use chrono::{DateTime, Utc};

use crate::db::{DatabaseConnection, DatabaseError};
use crate::config::CONFIG;

pub mod cri;
pub mod microsoft;
pub mod admins;

use cri::CRIUser;
use microsoft::MSUser;

pub(in self) type UserResult<T> = Result<T, UserError>;

#[derive(Clone, Serialize, Deserialize)]
pub struct User {
    #[serde(rename = "_key")]
    pub id: String,

    pub cri_user: cri::CRIUser,
    pub groups: Vec<u8>, // Group IDs

    pub session: Option<UserSession> // Only 'Some' if the user is logged
}

#[derive(Clone, Serialize, Deserialize)]
pub struct UserSession {
    pub token: String,
    pub expires_at: DateTime<Utc>,
    pub ms_user: MSUser,
    pub device_token: String
}

pub async fn update_users(db: &DatabaseConnection) -> UserResult<()> {
    if let Ok(s) = std::env::var("EPILYON_DONT_FETCH_CRI") {
        if s == "true" {
            warn!("CRI isn't fetched due to EPILYON_DONT_FETCH_CRI being true, user list may not be up to date");
            return Ok(())
        }
    }

    let users = cri::fetch_users(
        &CONFIG.cri_url,
        &CONFIG.cri_photos_url,
        &CONFIG.cri_accessor_username,
        &CONFIG.cri_accessor_password
    ).await.map_err(|e| UserError::CRIError { error: e })?;

    let all_users: Vec<&String> = users.iter()
        .map(|(_, u)| &u.username)
        .collect();

    let to_add_usernames: Vec<String> = db.single_query(
        r#"
        LET names = (
            FOR u IN users
                RETURN u.cri_user.username
        )
        FOR u in @users
            FILTER !POSITION(names, u)
            RETURN u
        "#, json!({
            "users": all_users
        })
    ).await?;

    let to_add: Vec<&(u32, CRIUser)> = users.iter()
        .filter(|(_, user)| to_add_usernames.contains(&user.username))
        .collect();

    // to_add will be moved in the for, so getting length here
    let added = to_add.len();

    for (id, user) in to_add {
        db.add("users", User {
            id: (*id).to_string(),

            cri_user: user.clone(),
            groups: Vec::new(),
            session: None
        }).await?;
    }

    if added > 0 {
        info!("Added {} new users to the database", added);
    } else {
        info!("User list is up to date");
    }

    Ok(())
}

pub async fn get_user_by_email(db: &DatabaseConnection, email: &str) -> UserResult<Option<User>> {
    let mut result: Vec<User> = db.single_query(
        r"
        FOR user IN users
            FILTER user.cri_user.email == @email
            RETURN user
        ",
        json!({
            "email": email
        })
    ).await?;

    if result.len() == 0 {
        Ok(None)
    } else {
        Ok(Some(result.swap_remove(0)))
    }
}

impl std::fmt::Display for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{} {}", self.cri_user.first_name, self.cri_user.last_name)
    }
}

#[derive(Debug, Fail)]
pub enum UserError {
    #[fail(display = "CRI request error : {}", error)]
    CRIError {
        error: cri::CRIError
    },

    #[fail(display = "Database request error : {}", error)]
    DatabaseError {
        error: DatabaseError
    },

    #[fail(display = "An entry is missing from the database")]
    MissingEntry {
        collection: String,
        key: String
    }
}

impl UserError {
    pub fn to_detailed_string(&self) -> String {
        use UserError::*;

        let mut result = String::new();
        result += &self.to_string();

        match self {
            CRIError { error } => {
                result = format!("CRI request error : {}", error.to_detailed_string());
            },
            DatabaseError { error } => {
                result = format!("Database request error : {}", error.to_detailed_string());
            },
            MissingEntry { collection, key } => {
                result = format!(" : Collection '{}' is missing entry '{}'", collection, key);
            }
        }

        result
    }
}

from_error!(DatabaseError, UserError, UserError::DatabaseError);
