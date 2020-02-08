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
use serde_json::json;
use log::error;
use actix_web::{
    web,
    get, post,
    HttpResponse,
    ResponseError,
    dev::HttpResponseBuilder,
    http::StatusCode
};

use crate::db::DatabaseConnection;
use crate::data::{get_data, refresh_user, DataError};
use crate::user::User;

pub fn configure(cfg: &mut web::ServiceConfig, db: web::Data<DatabaseConnection>) {
    cfg.service(
        web::scope("/")
            .app_data(db)
            .service(data_get)
    );
}

#[get("/get")]
pub async fn data_get(user: User, db: web::Data<DatabaseConnection>) -> Result<HttpResponse, DataError> {
    Ok(HttpResponse::Ok().json(json!({
        "success": true,
        "data": get_data(db.as_ref(), &user).await?
    })))
}

#[post("/refresh")]
pub async fn refresh(mut user: User, db: web::Data<DatabaseConnection>) -> Result<HttpResponse, DataError> {
    refresh_user(db.as_ref(), &mut user).await?;

    Ok(HttpResponse::Ok().json(json!({
        "success": true
    })))
}

impl ResponseError for DataError {
    fn status_code(&self) -> StatusCode {
        use DataError::*;

        match self {
            NotLogged =>
                StatusCode::FORBIDDEN,
            MSError { error }=> {
                error!("Microsoft error during auth request : {}", error);
                StatusCode::INTERNAL_SERVER_ERROR
            },
            DatabaseError { error } => {
                error!("Database error during auth request : {}", error);
                StatusCode::INTERNAL_SERVER_ERROR
            },
            PDFError { error } => {
                error!("PDF parsing error during auth request : {}", error);
                StatusCode::INTERNAL_SERVER_ERROR
            },
            DateParsingError { error } => {
                error!("Date parsing error during auth request : {}", error);
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }

    fn error_response(&self) -> HttpResponse {
        HttpResponseBuilder::new(self.status_code()).json(json!({
            "success": false,
            "error": format!("{}", self)
        }))
    }
}
