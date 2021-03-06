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
use log::warn;

use super::{User, UserError, UserResult};
use crate::db::DatabaseConnection;

pub async fn add_promo_infos(db: &DatabaseConnection, admin: &User) -> UserResult<()> {
    if has_admin_infos(db, &admin.cri_user.promo).await? {
        return Ok(())
    }

    db.add("admins", AdminInfo {
        promo: admin.cri_user.promo.clone(),
        admin: admin.id.clone(),
        delegates: Vec::new()
    }).await?;

    Ok(())
}

pub async fn is_admin(db: &DatabaseConnection, user: &User) -> UserResult<bool> {
    let infos = get_admin_infos(db, &user.cri_user.promo).await?;
    Ok(infos.admin == user.id)
}

pub async fn is_privileged(db: &DatabaseConnection, user: &User) -> UserResult<bool> {
    let infos = get_admin_infos(db, &user.cri_user.promo).await?;
    Ok(infos.admin == user.id || infos.delegates.contains(&user.cri_user.promo))
}

pub async fn get_admin(db: &DatabaseConnection, promo: &str) -> UserResult<Delegate> {
    let id = get_admin_infos(db, promo).await?.admin;

    match db.get::<User>("users", &id).await? {
        Some(user) => {
            Ok(Delegate::from(user))
        }
        None => {
            Err(UserError::MissingEntry {
                collection: "admins".to_string(),
                key: promo.to_string()
            })
        }
    }
}

pub async fn get_delegates(db: &DatabaseConnection, promo: &str) -> UserResult<Vec<Delegate>> {
    let ids = get_admin_infos(db, promo).await?.delegates;
    let mut result = Vec::<Delegate>::new();

    for id in ids {
        if let Some(user) = db.get::<User>("users", &id).await? {
            result.push(Delegate::from(user));
        } else {
            warn!(
                "An unknown user ID '{}' was registered as delegate \
                for promo '{}' but does not exist, skipping",
                id,
                promo
            );
        }
    }

    Ok(result)
}

pub async fn set_delegate(db: &DatabaseConnection, user: &User) -> UserResult<()> {
    let mut infos = get_admin_infos(db, &user.cri_user.promo).await?;
    if !infos.delegates.contains(&user.id) {
        infos.delegates.push(user.id.clone());
    }

    db.replace("admins", &infos.promo.clone(), infos).await?;

    Ok(())
}

pub async fn unset_delegate(db: &DatabaseConnection, user: &User) -> UserResult<()> {
    let mut infos = get_admin_infos(db, &user.cri_user.promo).await?;
    infos.delegates = infos.delegates.into_iter().filter(|id| *id != user.id).collect();

    db.replace("admins", &infos.promo.clone(), infos).await?;

    Ok(())
}

pub async fn has_admin_infos(db: &DatabaseConnection, promo: &str) -> UserResult<bool> {
    match get_admin_infos(db, promo).await {
        Ok(_) => Ok(true),
        Err(err) => match err {
            _err @ UserError::MissingEntry { .. } => Ok(false),
            err @ UserError::CRIError { .. } => Err(err),
            err @ UserError::DatabaseError { .. } => Err(err)
        }
    }
}

async fn get_admin_infos(db: &DatabaseConnection, promo: &str) -> UserResult<AdminInfo> {
    if let Some(infos) = db.get("admins", promo).await? {
        Ok(infos)
    } else {
        Err(UserError::MissingEntry {
            collection: String::from("admins"),
            key: format!("? where 'promo' = '{}'", promo)
        })
    }
}

#[derive(Serialize, Deserialize)]
struct AdminInfo {
    #[serde(rename = "_key")]
    promo: String,
    admin: String,
    delegates: Vec<String>
}

#[derive(Serialize, Deserialize)]
pub struct Delegate {
    name: String,
    email: String
}

impl From<User> for Delegate {
    fn from(user: User) -> Self {
        Delegate {
            name: format!("{}", user),
            email: user.cri_user.email.clone()
        }
    }
}