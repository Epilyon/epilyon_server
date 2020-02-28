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
use log::{info, warn, error, Level};
use fern::colors::{ColoredLevelConfig, Color};
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

    if let Err(e) = setup_logger() {
        eprintln!("Couldn't initialize logger : {}", e);
        return;
    }

    info!("Starting Epilyon server v{}", VERSION);
    info!("by Adrien 'Litarvan' Navratil");
    info!("---------------------------------------------------");

    let conn = db::open(
        &CONFIG.db_host,
        CONFIG.db_port,
        &CONFIG.db_user,
        &CONFIG.db_password,
        &CONFIG.db_database
    ).await;

    match conn {
        Ok(db) => {
            if let Err(e) = cri_startup(&db).await {
                error!("Error while loading users from the CRI");
                error!("{}", e.to_detailed_string());

                return;
            }

            RefreshActor {
                db: db.clone()
            }.start();

            if let Err(e) = http::start(&CONFIG.address, CONFIG.port, db).await {
                error!("Error while running the HTTP server : {}", e);
            }
        },
        Err(e) => {
            error!("Error while setting up database connection");
            error!("{}", e.to_detailed_string());
        }
    }
}

fn setup_logger() -> Result<(), fern::InitError> {
    let colors = ColoredLevelConfig::new()
        .info(Color::Green)
        .warn(Color::Yellow)
        .error(Color::Red);

    let base = fern::Dispatch::new()
        .level(log::LevelFilter::Info);

    let stdout_log = fern::Dispatch::new()
        .format(move |out, message, record| {
            let target = record.target();
            let mut target_with_pad = " ".repeat((30i16 - target.len() as i16).max(0) as usize) + target;

            if record.level() != Level::Error {
                target_with_pad = " ".to_owned() + &target_with_pad;
            }

            out.finish(format_args!(
                "{} {} {} > {}",
                chrono::Local::now().format("[%Y-%m-%d] (%H:%M:%S%.3f)"),
                colors.color(record.level()),
                target_with_pad,
                message
            ))
        })
        .chain(std::io::stdout());

    let file_log = fern::Dispatch::new()
        .format(move |out, message, record| {
            let pad = " ".repeat((30i16 - record.target().len() as i16).max(0) as usize);
            let level_pad = if record.level() == Level::Error { "" } else { " " };

            out.finish(format_args!(
                "{} [{}{}] [{}]{} | {}",
                chrono::Local::now().format("[%Y-%m-%d] (%H:%M:%S%.3f)"),
                record.level(),
                level_pad,
                record.target(),
                pad,
                message
            ))
        })
        .chain(fern::log_file("epilyon.log")?);

    base
        .chain(file_log)
        .chain(stdout_log)
        .level_for("lopdf", log::LevelFilter::Warn)
        .apply()?;

    Ok(())
}

async fn cri_startup(db: &DatabaseConnection) -> Result<(), UserError> {
    if let Err(e) = user::update_users(&db).await {
        match e {
            UserError::CRIError { error } => {
                let count: JsonValue = db.single_query(
                    "RETURN COUNT(users)",
                    json!({})
                ).await?;

                if let Some(0i64) = count[0].as_i64() {
                    Err(UserError::CRIError { error })
                } else {
                    warn!("CRI error during user update : {}", error);
                    warn!("CRI is down, but there are users in the database, continuing anyway");

                    Ok(())
                }
            },
            // Prevents ownership errors
            err @ UserError::MissingEntry { .. } => Err(err), // Can't happen
            err @ UserError::DatabaseError { .. } => Err(err)
        }
    } else {
        Ok(())
    }
}
