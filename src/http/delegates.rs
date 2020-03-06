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
use log::{info, warn, error};
use failure::Fail;
use actix_web::{
    web,
    post,
    HttpResponse,
    ResponseError,
    dev::HttpResponseBuilder,
    http::StatusCode
};

use crate::db::{DatabaseConnection, DatabaseError};
use crate::user::{User, UserError, get_user_by_email};
use crate::user::admins::{is_admin, set_delegate, unset_delegate, is_privileged};
use crate::data::DataError;

type DelegatesResult<T> = Result<T, DelegatesError>;

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
) -> DelegatesResult<HttpResponse> {
    if !is_admin(db.as_ref(), &user).await? {
        return Err(DelegatesError::Unauthorized);
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
        Err(DelegatesError::UnknownUser {
            email: data.email.clone()
        })
    }
}

#[post("/remove")]
pub async fn remove_delegate(
    user: User,
    db: web::Data<DatabaseConnection>,
    data: web::Json<DelegateData>
) -> DelegatesResult<HttpResponse> {
    if !is_admin(db.as_ref(), &user).await? {
        return Err(DelegatesError::Unauthorized);
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
) -> DelegatesResult<HttpResponse> {
    if !is_privileged(db.as_ref(), &user).await? {
        return Err(DelegatesError::Unauthorized);
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

#[derive(Debug, Fail)]
pub enum DelegatesError {
    #[fail(display = "You don't have the required privileges to do that")]
    Unauthorized,

    #[fail(display = "Can't find any user with email '{}'", email)]
    UnknownUser {
        email: String
    },

    #[fail(display = "{}", error)]
    DatabaseError {
        error: DatabaseError
    },

    #[fail(display = "{}", error)]
    UserError {
        error: UserError
    },

    #[fail(display = "{}", error)]
    DataError {
        error: DataError
    }
}

impl ResponseError for DelegatesError {
    fn status_code(&self) -> StatusCode {
        use DelegatesError::*;

        match self {
            Unauthorized => StatusCode::FORBIDDEN,
            UnknownUser { .. } => StatusCode::BAD_REQUEST,
            UserError { .. } | DatabaseError { .. } | DataError { .. }=> StatusCode::INTERNAL_SERVER_ERROR
        }
    }

    fn error_response(&self) -> HttpResponse {
        if let DelegatesError::UserError { error } = self {
            error!("User error dropped during delegates request : {}", error.to_detailed_string());
        } else if let DelegatesError::DatabaseError { error } = self {
            error!("Database error dropped during delegates request : {}", error.to_detailed_string());
        } else if let DelegatesError::DataError { error } = self {
            error!("Data error dropped during delegates request : {}", error.to_detailed_string());
        }

        HttpResponseBuilder::new(self.status_code()).json(json!({
            "success": false,
            "error": format!("{}", self)
        }))
    }
}

from_error!(UserError, DelegatesError, DelegatesError::UserError);
from_error!(DatabaseError, DelegatesError, DelegatesError::DatabaseError);
from_error!(DataError, DelegatesError, DelegatesError::DataError);
