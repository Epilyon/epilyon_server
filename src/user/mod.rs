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

use cri::CRIUser;
use microsoft::MSUser;

#[derive(Clone, Serialize, Deserialize)]
pub struct User {
    pub _key: String,
    pub id: u32,

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

pub async fn update_users(db: &DatabaseConnection) -> Result<(), UserError> {
    if let Ok(s) = std::env::var("EPILYON_DONT_FETCH_CRI") {
        if s == "true" {
            warn!("CRI isn't fetched due to EPILYON_DONT_FETCH_CRI being true, user list may not be up to date");
            return Ok(())
        }
    }

    let users = cri::fetch_users(
        &CONFIG.cri_url,
        &CONFIG.cri_accessor_username,
        &CONFIG.cri_accessor_password,
        &CONFIG.cri_promos
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
        db.add("users", json!({
            "id": *id,

            "cri_user": user.clone(),
            "groups": Vec::<String>::new(),

            "session": Option::<UserSession>::None
        })).await?;
    }

    if added > 0 {
        info!("Added {} new users to the database", added);
    } else {
        info!("User list is up to date");
    }

    Ok(())
}

#[derive(Debug, Fail)]
pub enum UserError {
    #[fail(display = "CRI request error : {}", error)]
    CRIError {
        error: cri::CRIError
    },

    #[fail(display = "Database request error : This is very bad, please contact the devs")]
    DatabaseError {
        error: DatabaseError
    }
}

from_error!(DatabaseError, UserError, UserError::DatabaseError);
