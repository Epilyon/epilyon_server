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

use serde::Deserialize;
use serde_json::json;
use log::{info, warn};
use actix_web::{web, post, HttpResponse};

use crate::db::DatabaseConnection;
use crate::user::{User, get_user_by_email};
use crate::user::admins::{is_admin, set_delegate, unset_delegate, is_privileged};
use crate::data::{DataError, DataResult};

pub fn configure(cfg: &mut web::ServiceConfig, db: web::Data<DatabaseConnection>) {
    cfg.service(
        web::scope("/")
            .app_data(db)
            .service(add_delegate)
            .service(remove_delegate)
            .service(notify_all)
    );
}

#[post("/add")]
pub async fn add_delegate(
    user: User,
    db: web::Data<DatabaseConnection>,
    data: web::Json<DelegateData>
) -> DataResult<HttpResponse> {
    if !is_admin(db.as_ref(), &user).await? {
        return Err(DataError::Unauthorized);
    }

    if let Some(user) = get_user_by_email(db.as_ref(), &data.email).await? {
        set_delegate(db.as_ref(), &user).await?;

        info!(
            "User '{} {}' is now a delegate of promo '{}'",
            user.cri_user.first_name,
            user.cri_user.last_name,
            user.cri_user.promo
        );

        Ok(HttpResponse::Ok().json(json!({
            "success": true,
            "name": &format!("{} {}", user.cri_user.first_name, user.cri_user.last_name)
        })))
    } else {
        Err(DataError::UnknownUser {
            email: data.email.clone()
        })
    }
}

#[post("/remove")]
pub async fn remove_delegate(
    user: User,
    db: web::Data<DatabaseConnection>,
    data: web::Json<DelegateData>
) -> DataResult<HttpResponse> {
    if !is_admin(db.as_ref(), &user).await? {
        return Err(DataError::Unauthorized);
    }

    if let Some(user) = get_user_by_email(db.as_ref(), &data.email).await? {
        unset_delegate(db.as_ref(), &user).await?;

        info!(
            "User '{} {}' is not anymore a delegate of promo '{}'",
            user.cri_user.first_name,
            user.cri_user.last_name,
            user.cri_user.promo
        );
    } else {
        warn!(
            "An unknown user with email '{}' was asked to be removed \
            from the delegates of promo '{}', skipping",
            data.email,
            user.cri_user.promo
        );
    }

    Ok(HttpResponse::Ok().json(json!({
        "success": true
    })))
}

#[post("/notify")]
pub async fn notify_all(
    user: User,
    db: web::Data<DatabaseConnection>,
    data: web::Json<NotifyData>
) -> DataResult<HttpResponse> {
    if !is_privileged(db.as_ref(), &user).await? {
        return Err(DataError::Unauthorized);
    }

    crate::data::notify_all(db.as_ref(), &user, &data.content).await?;

    Ok(HttpResponse::Ok().json(json!({
        "success": true
    })))
}

#[derive(Deserialize)]
pub struct DelegateData {
    email: String
}

#[derive(Deserialize)]
pub struct NotifyData {
    content: String
}
