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
use serde_json::json;

use super::{User, UserError, UserResult};
use crate::db::DatabaseConnection;

pub async fn add_promo_infos(db: &DatabaseConnection, admin: &User) -> UserResult<()> {
    if has_admin_infos(db, &admin.cri_user.promo).await? {
        return Ok(())
    }

    db.add("admins", json!({
        "promo": &admin.cri_user.promo,
        "admin": admin.id,
        "delegates": Vec::<u32>::new()
    })).await?;

    Ok(())
}

pub async fn is_admin(db: &DatabaseConnection, user: &User) -> UserResult<bool> {
    let infos = get_admin_infos(db, &user.cri_user.promo).await?;
    Ok(infos.admin == user.id)
}

pub async fn get_delegates(db: &DatabaseConnection, promo: &str) -> UserResult<Vec<u32>> {
    let infos = get_admin_infos(db, promo).await?;
    Ok(infos.delegates)
}

pub async fn set_delegate(db: &DatabaseConnection, user: &User) -> UserResult<()> {
    let mut infos = get_admin_infos(db, &user.cri_user.promo).await?;
    infos.delegates.push(user.id);

    db.replace("admins", &infos._key.clone(), infos).await?;

    Ok(())
}

pub async fn unset_delegate(db: &DatabaseConnection, user: &User) -> UserResult<()> {
    let mut infos = get_admin_infos(db, &user.cri_user.promo).await?;
    infos.delegates = infos.delegates.into_iter().filter(|&id| id != user.id).collect();

    db.replace("admins", &infos._key.clone(), infos).await?;

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
    let mut result: Vec<AdminInfo> = db.single_query(
        r"
            FOR obj IN admins
                FILTER obj.promo == @promo
                RETURN obj
        ",
        json!({
            "promo": promo
        })
    ).await?;

    if result.len() == 0 {
        Err(UserError::MissingEntry {
            collection: String::from("admins"),
            key: format!("? where 'promo' = '{}'", promo)
        })
    } else {
        Ok(result.swap_remove(0))
    }
}

#[derive(Serialize, Deserialize)]
struct AdminInfo {
    _key: String,
    promo: String,
    admin: u32,
    delegates: Vec<u32>
}