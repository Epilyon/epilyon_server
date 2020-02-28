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
use log::{info, error};
use failure::Fail;
use actix_web::{
    web,
    get, post, delete,
    HttpRequest, HttpResponse,
    ResponseError,
    dev::HttpResponseBuilder,
    http::StatusCode
};

use crate::db::DatabaseConnection;
use crate::user::{User, UserError};
use crate::user::admins::{is_admin, get_delegates, set_delegate, unset_delegate};

type DelegatesResult<T> = Result<T, DelegatesError>;

pub fn configure(cfg: &mut web::ServiceConfig, db: web::Data<DatabaseConnection>) {
    cfg.service(
        web::scope("/")
            .app_data(db)
            .service(delegates)
            .service(add_delegate)
            .service(remove_delegate)
    );
}

#[get("/")]
pub async fn delegates(user: User, db: web::Data<DatabaseConnection>) -> DelegatesResult<HttpResponse> {
    /*let ids = get_delegates(db.as_resf(), &user.cri_user.promo).await?;
    let delegates =

    Ok(HttpResponse::Ok().json(json!({
        "success": true,
        "delegates": get_data(db.as_ref(), &user).await?
    })))*/

    unimplemented!()
}

#[post("/")]
pub async fn add_delegate(
    user: User,
    db: web::Data<DatabaseConnection>,
    data: web::Json<DelegateData>
) -> DelegatesResult<HttpResponse> {
    unimplemented!()
}

#[delete("/")]
pub async fn remove_delegate(
    user: User,
    db: web::Data<DatabaseConnection>,
    data: web::Json<DelegateData>
) -> DelegatesResult<HttpResponse> {
    unimplemented!()
}

#[derive(Deserialize)]
pub struct DelegateData {
    email: String
}

#[derive(Debug, Fail)]
pub enum DelegatesError {
    #[fail(display = "Only the promo admin can do that")]
    Unauthorized,

    #[fail(display = "Can't find any user with email '{}'", email)]
    UnknownUser {
        email: String
    },

    #[fail(display = "{}", error)]
    UserError {
        error: UserError
    }
}

impl ResponseError for DelegatesError {
    fn status_code(&self) -> StatusCode {
        use DelegatesError::*;

        match self {
            Unauthorized => StatusCode::FORBIDDEN,
            UnknownUser { .. } => StatusCode::BAD_REQUEST,
            UserError { .. } => StatusCode::INTERNAL_SERVER_ERROR
        }
    }

    fn error_response(&self) -> HttpResponse {
        if let DelegatesError::UserError { error } = self {
            error!("User error dropped during delegates related request : {}", error.to_detailed_string());
        }

        HttpResponseBuilder::new(self.status_code()).json(json!({
            "success": false,
            "error": format!("{}", self)
        }))
    }
}

from_error!(UserError, DelegatesError, DelegatesError::UserError);
