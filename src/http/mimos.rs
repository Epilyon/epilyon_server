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
use actix_web::{web, post, HttpResponse};

use crate::db::DatabaseConnection;
use crate::user::User;
use crate::data::{mimos, DataResult};
use crate::data::mimos::Mimos;

pub fn configure(cfg: &mut web::ServiceConfig, db: web::Data<DatabaseConnection>) {
    cfg.service(
        web::scope("/")
            .app_data(db)
            .service(add_mimos)
            .service(remove_mimos)
    );
}

#[post("/add")]
pub async fn add_mimos(
    user: User,
    db: web::Data<DatabaseConnection>,
    data: web::Json<Mimos>
) -> DataResult<HttpResponse> {
    mimos::add_mimos(db.as_ref(), &user, data.into_inner()).await?;

    Ok(HttpResponse::Ok().json(json!({
        "success": true
    })))
}

#[post("/remove")]
pub async fn remove_mimos(
    user: User,
    db: web::Data<DatabaseConnection>,
    data: web::Json<RemoveMimosData>
) -> DataResult<HttpResponse> {
    mimos::remove_mimos(db.as_ref(), &user, data.number, &data.subject).await?;

    Ok(HttpResponse::Ok().json(json!({
        "success": true
    })))
}

#[derive(Deserialize)]
pub struct RemoveMimosData {
    number: u8,
    subject: String
}