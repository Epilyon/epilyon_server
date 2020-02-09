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
use std::time::Duration as StdDuration;

use serde::Serialize;
use serde_json::json;
use time::Duration;
use chrono::Utc;
use actix::prelude::{Actor, Context, AsyncContext};
use failure::Fail;
use log::{info, error};

use crate::user::{User, microsoft};
use crate::db::{DatabaseConnection, DatabaseError};
use crate::user::microsoft::MSError;

mod qcm;
mod pdf;
mod push_notif;

use pdf::PDFError;
use qcm::{NextQCM, QCMResult};

const REFRESH_RATE: u64 = 5 * 60; // In seconds (= 5 minutes)

#[derive(Serialize)]
pub struct UserData {
    next_qcm: Option<NextQCM>,
    history: Vec<QCMResult>
}

// TODO: Outlook push notif for QCMs

async fn refresh(db: DatabaseConnection) {
    let logged_users: Result<Vec<User>, DatabaseError> = db.single_query(
        r"
            FOR u IN users
                FILTER u.session != null
                FILTER u.session.expires_at > @time
                RETURN u
        ",
        json!({
            "time": Utc::now().timestamp()
        })
    ).await;

    match logged_users {
        Ok(users) => {
            for mut user in users {
                if let Err(e) = refresh_user(&db, &mut user).await {
                    error!(
                        "Error while refreshing user '{} {}' : {}",
                        user.cri_user.first_name,
                        user.cri_user.last_name,
                        e
                    );

                    if let DataError::DatabaseError { error } = e {
                        error!("Error is a database error : {}", error);
                    }

                    error!("Skipping the refresh process for this user");
                }
            }
        },
        Err(e) => {
            error!("Database error while retrieving logged users : {}", e);
            error!("Skipping the whole refresh process");
        }
    }
}

pub async fn refresh_user(db: &DatabaseConnection, user: &mut User) -> Result<(), DataError> {
    let session = user.session.as_mut().ok_or(DataError::NotLogged)?;

    if Utc::now() - Duration::minutes(5) > session.ms_user.expires_at {
        session.ms_user = microsoft::refresh(&session.ms_user).await?;
    }

    db.update("users", &user._key, user.clone()).await?;

    let qcms = qcm::fetch_qcms(db, user).await?;
    if let Some(qcm) = qcms.get(0) {
        push_notif::notify(
            user,
            "Résultats du QCM",
            &format!(
                "Résultats du QCM : {}",
                match qcm.grades.len() {
                    2 => "Partie 2 reçue uniquement",
                    5 => "Partie 1 reçue",
                    7 => "Parties 1 & 2 reçues",
                    _ => "Notes reçues" // Can't happen (normally)
                }
            )
        ).await?;
    }

    Ok(())
}

pub async fn get_data(db: &DatabaseConnection, user: &User) -> Result<UserData, DataError> {
    Ok(UserData {
        next_qcm: qcm::get_next_qcm(db, user).await?,
        history: qcm::get_qcm_history(db, user).await?
    })
}

pub struct RefreshActor {
    pub db: DatabaseConnection
}

impl Actor for RefreshActor {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        info!("Started refresh process (every {} seconds)", REFRESH_RATE);

        ctx.run_interval(StdDuration::from_secs(REFRESH_RATE), move |a, ctx| {
            ctx.spawn(actix::fut::wrap_future::<_, Self>(refresh(a.db.clone())));
        });
    }
}

#[derive(Fail, Debug)]
pub enum DataError {
    #[fail(display = "Database request error : This is very bad, please contact the devs")]
    DatabaseError {
        error: DatabaseError
    },

    #[fail(display = "You are not logged, your data can't be refreshed")]
    NotLogged,

    #[fail(display = "Microsoft remote error : {}", error)]
    MSError {
        error: MSError
    },

    #[fail(display = "PDF parsing error : {}", error)]
    PDFError {
        error: PDFError
    },

    #[fail(display = "Date parsing error : {}", error)]
    DateParsingError {
        error: chrono::ParseError
    },

    #[fail(display = "Push notification error : {}", error)]
    PushNotifError {
        error: reqwest::Error
    }
}

from_error!(DatabaseError, DataError, DataError::DatabaseError);
from_error!(MSError, DataError, DataError::MSError);
from_error!(PDFError, DataError, DataError::PDFError);
from_error!(chrono::ParseError, DataError, DataError::DateParsingError);
