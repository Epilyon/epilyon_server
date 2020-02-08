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
use log::{info, warn, error};
use serde_json::{json, Value as JsonValue};
use actix::Actor;

const VERSION: &str = "0.1.0";

#[macro_use]
mod macros;

mod data;
mod http;
mod user;
mod config;
mod db;
mod sync;

use config::CONFIG;
use db::DatabaseConnection;
use user::UserError;
use data::RefreshActor;

#[actix_rt::main]
async fn main() {
    if std::env::var("EPILYON_LOG").is_err() {
        std::env::set_var("EPILYON_LOG", "warn,epilyon_server=info");
    }

    if let Err(e) = pretty_env_logger::try_init_custom_env("EPILYON_LOG") {
        eprintln!("Couldn't initialize logger : {}", e);
        return;
    }

    info!("Starting Epilyon server v{}", VERSION);
    info!("by Adrien 'Litarvan' Navratil");
    info!("---------------------------------------------------");

    match startup().await {
        Ok(db) => {
            RefreshActor {
                db: db.clone()
            }.start();

            if let Err(e) = http::start(&CONFIG.address, CONFIG.port, db).await {
                error!("Error while running the HTTP server : {}", e);
            }
        },
        Err(e) => error!("Error during startup phase : {}", e)
    }
}

async fn startup() -> Result<DatabaseConnection, failure::Error> {
    let conn = db::open(
        &CONFIG.db_host,
        CONFIG.db_port,
        &CONFIG.db_user,
        &CONFIG.db_password,
        &CONFIG.db_database
    ).await?;

    let res = user::update_users(&conn).await;
    if let Err(e) = res {
        match e {
            UserError::CRIError { error } => {
                let count: JsonValue = conn.single_query(
                    "RETURN COUNT(users)",
                    json!({})
                ).await?;

                if let Some(0i64) = count[0].as_i64() {
                    Err(error.into())
                } else {
                    warn!("CRI error during user update : {}", error);
                    warn!("CRI is down, but there are users in the database, continuing anyway");

                    Ok(conn)
                }
            },
            // Prevents ownership errors
            err @ UserError::DatabaseError { .. } => Err(err.into())
        }
    } else {
        Ok(conn)
    }
}