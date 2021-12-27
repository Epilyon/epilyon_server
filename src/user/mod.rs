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
use chrono::{DateTime, Utc};

use crate::db::{DatabaseConnection, DatabaseError};

pub mod cri;
pub mod microsoft;
pub mod admins;
pub mod epitaf;

use cri::CRIError;
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

pub async fn get_user(db: &DatabaseConnection, email: &str) -> UserResult<User> {
    let matches: Vec<User> = db.single_query(
        r"
            FOR user IN users
                FILTER user.cri_user.email == @email
                    RETURN user
        ", json!({
            "email": email
        })
    ).await?;

    if let Some(user) = matches.into_iter().nth(0) {
        return Ok(user)
    }

    let (id, user) = cri::fetch_user(email).await?;
    let user = User {
        id: id.to_string(),

        cri_user: user.clone(),
        groups: Vec::new(),
        session: None
    };

    db.add("users", user.clone()).await?;

    Ok(user)
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
from_error!(CRIError, UserError, UserError::CRIError);
