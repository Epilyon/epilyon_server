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
use log::{info, error};
use futures::StreamExt;
use percent_encoding::percent_decode_str;
use actix_web::{
    web,
    get, post,
    HttpRequest, HttpResponse,
    ResponseError,
    dev::HttpResponseBuilder,
    http::StatusCode
};

use crate::db::DatabaseConnection;
use crate::data::{get_data, refresh_user, handle_notification, DataResult, DataError};
use crate::user::User;
use crate::user::microsoft::{MSValue, Notification};

pub fn configure(cfg: &mut web::ServiceConfig, db: web::Data<DatabaseConnection>) {
    cfg.service(
        web::scope("/")
            .app_data(db)
            .service(data_get)
            .service(refresh)
            .service(notify)
    );
}

#[get("/get")]
pub async fn data_get(user: User, db: web::Data<DatabaseConnection>) -> DataResult<HttpResponse> {
    Ok(HttpResponse::Ok().json(json!({
        "success": true,
        "data": get_data(db.as_ref(), &user).await?
    })))
}

#[post("/refresh")]
pub async fn refresh(mut user: User, db: web::Data<DatabaseConnection>) -> DataResult<HttpResponse> {
    // TODO: Rate limit this

    refresh_user(db.as_ref(), &mut user).await?;

    Ok(HttpResponse::Ok().json(json!({
        "success": true
    })))
}

#[post("/notify")]
pub async fn notify(
    request: HttpRequest,
    db: web::Data<DatabaseConnection>,
    mut payload: web::Payload
) -> DataResult<HttpResponse> {
    let query = request.query_string();

    if query.len() > 0 {
        info!("Received /notify call with query '{}'", query);
    }

    if query.starts_with("validationToken=") {
        let token = String::from(&query[16..]);
        let decoded = percent_decode_str(&token).decode_utf8()?.replace("+", " ");

        return Ok(HttpResponse::Ok().body(String::from(&*decoded)));
    }

    let mut bytes = web::BytesMut::new();
    while let Some(item) = payload.next().await {
        bytes.extend_from_slice(&item?);
    }

    let body = std::str::from_utf8(&bytes)?;
    let mut result: MSValue<Vec<Notification>> = serde_json::from_str(body)
        .map_err(|e| DataError::JsonParsingError {
            payload: body.to_owned(),
            error: e
        })?;

    if result.value.len() > 0 {
        if let Err(e) = handle_notification(db.get_ref(), result.value.swap_remove(0)).await {
            error!("Error while handling a notification : {}", e.to_detailed_string());
            error!("Skipping");
        }
    }

    Ok(HttpResponse::Accepted().finish())
}

impl ResponseError for DataError {
    fn status_code(&self) -> StatusCode {
        use DataError::*;

        match self {
            NotLogged =>
                StatusCode::FORBIDDEN,
            PayloadDecodingError { .. } | JsonParsingError { .. } | InvalidClientState { .. } =>
                StatusCode::BAD_REQUEST,
            _ =>
                StatusCode::INTERNAL_SERVER_ERROR
        }
    }

    fn error_response(&self) -> HttpResponse {
        error!("A data error was dropped during a request : {}", self.to_detailed_string());

        HttpResponseBuilder::new(self.status_code()).json(json!({
            "success": false,
            "error": format!("{}", self)
        }))
    }
}
