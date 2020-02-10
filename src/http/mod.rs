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
use std::io::Error as IOError;

use failure::Fail;
use log::info;
use actix_web::{
    web, http,
    App, HttpServer,
    middleware::Logger
};

use crate::db::DatabaseConnection;

mod auth;
mod data;
pub mod jwt;

pub async fn start(address: &str, port: u16, db: DatabaseConnection) -> Result<(), HttpError> {
    let db_data = web::Data::new(db);

    let address = format!("{}:{}", address, port);
    let server = HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .service(web::scope("/auth").configure(|c| {
                auth::configure(c, db_data.clone())
            }))
            .service(web::scope("/data").configure(|c| {
                data::configure(c, db_data.clone())
            }))
    })
        .bind(&address).map_err(|e| HttpError::BindError { address: address.clone(), error: e })?
        .run();

    info!("Listening on http://{}...", address);

    server.await.map_err(|e| HttpError::ServerError { error: e })
}

#[derive(Debug, Fail)]
pub enum HttpError {
    #[fail(display = "Couldn't bind to address '{}' : {}", address, error)]
    BindError {
        address: String,
        error: IOError
    },

    #[fail(display = "HTTP server I/O error : {}", error)]
    ServerError {
        error: IOError
    }
}
