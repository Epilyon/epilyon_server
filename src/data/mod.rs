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
use std::sync::{Arc, Mutex};
use std::collections::HashMap;

use serde::{Serialize, Deserialize};
use serde_json::json;
use time::Duration;
use chrono::Utc;
use actix::prelude::{Actor, Context, AsyncContext};
use failure::Fail;
use log::{info, error};
use lazy_static::lazy_static;

use crate::config::CONFIG;
use crate::user::{User, microsoft};
use crate::db::{DatabaseConnection, DatabaseError};
use crate::user::microsoft::{MSError, Notification, MSSubscription};
use crate::sync::EpiLock;

mod qcm;
mod pdf;
mod push_notif;

use pdf::PDFError;
use qcm::{NextQCM, QCMResult};

const REFRESH_RATE: u64 = 30 * 60; // In seconds (= 30 minutes)

lazy_static! {
    static ref REFRESH_LOCKS: Mutex<HashMap<u32, Arc<Mutex<bool>>>> = Mutex::new(HashMap::new());
}

#[derive(Serialize)]
pub struct UserData {
    next_qcm: Option<NextQCM>,
    history: Vec<QCMResult>
}

pub async fn refresh(db: DatabaseConnection) {
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
    let user_lock = get_user_lock(user);
    let guard = user_lock.epilock();

    // Dirty part ends here

    let user_clone = user.clone();
    let session = user.session.as_mut().ok_or(DataError::NotLogged)?;

    if Utc::now() - Duration::minutes(5) > session.ms_user.expires_at {
        session.ms_user = microsoft::refresh(&session.ms_user).await?;
    }

    db.update("users", &user._key, user_clone).await?;

    let subscription: Vec<MSSubscription> = db.single_query(
        r"
            FOR subscription IN subscriptions
                FILTER subscription.user == @id
                RETURN subscription
        ",
        json!({
            "id": &user.id
        })
    ).await?;

    if subscription.len() == 0 {
        let subscription = microsoft::subscribe(
            &session.ms_user,
            "/me/mailfolders('inbox')/messages"
        ).await?;

        db.add("subscriptions", json!({
            "user": &user.id,
            "id": &subscription.id,
            "expires_at": &subscription.expirationDateTime
        })).await?;
    } else {
        // TODO: Renew subscription if needed
    }

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

    if *guard {
        // So that the Mutex is unlocked here
        print!("");
    }

    Ok(())
}

// This is dirty but needed to prevent two refreshes being done at the same time
pub fn get_user_lock(user: &User) -> Arc<Mutex<bool>> {
    let mut locks = REFRESH_LOCKS.epilock();

    if !locks.contains_key(&user.id) {
        locks.insert(user.id, Arc::new(Mutex::new(true)));
    }

    locks.get(&user.id).unwrap().clone()
}

pub async fn get_data(db: &DatabaseConnection, user: &User) -> Result<UserData, DataError> {
    Ok(UserData {
        next_qcm: qcm::get_next_qcm(db, user).await?,
        history: qcm::get_qcm_history(db, user).await?
    })
}

pub async fn handle_notification(db: &DatabaseConnection, notification: Notification) -> Result<(), DataError> {
    if &notification.clientState != &CONFIG.ms_webhook_key {
        return Err(DataError::InvalidClientState);
    }

    // Multiple notifications are sent for each email received, but we must process only one
    if &notification.changeType != "created" {
        return Ok(());
    }

    let mut result: Vec<User> = db.single_query(
        r"
            LET user_id = (
                FOR subscription IN subscriptions
                    FILTER subscription.id == @id
                    RETURN subscription.user
            )

            FOR uid IN user_id
                FOR user IN users
                    FILTER user.id == uid
                    RETURN user
        ",
        json!({
            "id": notification.subscriptionId
        })
    ).await?;

    if result.len() > 0 {
        let mut user = result.swap_remove(0);

        if let Err(e) = refresh_user(db, &mut user).await {
            println!("Data error while processing MS notification : {}", e);
        }

        // We de not return an error to not panic MS APIs
        Ok(())
    } else {
        Ok(())
    }
}

pub async fn remove_subscriptions_for(db: &DatabaseConnection, user: &User) -> Result<(), DataError> {
    let subscriptions: Vec<SubscriptionEntry> = db.single_query(
        r"
            FOR subscription IN subscriptions
                FILTER subscription.user == @id
                RETURN {
                    key: subscription._key,
                    id: subscription.id
                }
        ",
        json!({
            "id": &user.id
        })
    ).await?;

    let session = user.session.as_ref().ok_or(DataError::NotLogged)?;

    for subscription in subscriptions {
        microsoft::unsubscribe(&session.ms_user, &subscription.id).await?;
        db.remove("subscriptions", &subscription.key).await?;
    }

    Ok(())
}

#[derive(Deserialize)]
struct SubscriptionEntry {
    key: String,
    id: String
}

pub struct RefreshActor {
    pub db: DatabaseConnection
}

impl Actor for RefreshActor {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        info!("Started refresh process (every {} seconds)", REFRESH_RATE);

        ctx.spawn(actix::fut::wrap_future::<_, Self>(refresh(a.db.clone())));

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
    },

    #[fail(display = "Unable to read request payload : {}", error)]
    PayloadReadingError {
        error: actix_http::error::PayloadError
    },

    #[fail(display = "Unable to decode request payload as a string : {}", error)]
    PayloadDecodingError {
        error: std::str::Utf8Error
    },

    #[fail(display = "Unable to decode request payload as json : {}", error)]
    JsonParsingError {
        error: serde_json::Error
    },

    #[fail(display = "Client state does not correspond")]
    InvalidClientState
}

from_error!(DatabaseError, DataError, DataError::DatabaseError);
from_error!(MSError, DataError, DataError::MSError);
from_error!(PDFError, DataError, DataError::PDFError);
from_error!(chrono::ParseError, DataError, DataError::DateParsingError);
from_error!(actix_http::error::PayloadError, DataError, DataError::PayloadReadingError);
from_error!(std::str::Utf8Error, DataError, DataError::PayloadDecodingError);
from_error!(serde_json::Error, DataError, DataError::JsonParsingError);
