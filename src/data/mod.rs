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

use log::{info, warn, error};
use serde::Serialize;
use serde_json::json;
use time::Duration;
use chrono::Utc;
use actix::prelude::{Actor, Context, AsyncContext};
use failure::Fail;
use lazy_static::lazy_static;

use crate::config::CONFIG;
use crate::user::{User, microsoft, UserError};
use crate::db::{DatabaseConnection, DatabaseError};
use crate::user::microsoft::{MSError, Notification, MSSubscription};
use crate::user::admins::{Delegate, get_admin, get_delegates};
use crate::sync::EpiLock;

mod qcm;
pub mod mimos;
mod pdf;
mod push_notif;

use pdf::PDFError;
use qcm::{NextQCM, QCMResult};
use mimos::Mimos;

pub type DataResult<T> = Result<T, DataError>;

const REFRESH_RATE: u64 = 2 * 24 * 60 * 60; // In seconds (= 2 days)

lazy_static! {
    static ref REFRESH_LOCKS: Mutex<HashMap<String, Arc<Mutex<bool>>>> = Mutex::new(HashMap::new());
}

#[derive(Serialize)]
pub struct UserData {
    admin: Delegate,
    delegates: Vec<Delegate>,

    next_qcm: Option<NextQCM>,
    qcm_history: Vec<QCMResult>,
    mimos: Vec<Mimos>
}

pub async fn refresh_all(db: &DatabaseConnection) {
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
            let user_count = users.len();
            let time = time::now();

            info!("Refreshing {} users...", user_count);

            for mut user in users {
                if let Err(e) = refresh_user(&db, &mut user).await {
                    error!(
                        "Error while refreshing user '{} {}' : {}",
                        user.cri_user.first_name,
                        user.cri_user.last_name,
                        e.to_detailed_string()
                    );

                    error!("Skipping the refresh process for this user");
                }
            }

            let elapsed = (time::now() - time).num_milliseconds() as f32 / 1000.0;
            info!("Successfully refreshed {} users in {} seconds", user_count, elapsed);
        },
        Err(e) => {
            error!("Database error while fetching logged users : {}", e.to_detailed_string());
            error!("Skipping current refresh");
        }
    }
}

pub async fn refresh_user(db: &DatabaseConnection, user: &mut User) -> DataResult<()> {
    let user_lock = get_user_lock(user);
    let guard = user_lock.epilock();

    // Dirty part ends here

    let user_clone = user.clone();
    let session = user.session.as_mut().ok_or(DataError::NotLogged)?;

    info!("Refreshing user '{} {}'", user_clone.cri_user.first_name, user_clone.cri_user.last_name);

    if Utc::now() - Duration::minutes(5) > session.ms_user.expires_at {
        // TODO: Remove session on refresh token expiration (error_codes includes 700082)
        session.ms_user = microsoft::refresh(&session.ms_user).await?;
    }

    db.update("users", &user.id, user_clone).await?;

    if std::env::var("EPILYON_DONT_SUBSCRIBE").is_err() {
        let mut subscriptions: Vec<MSSubscription> = db.single_query(
            r"
            FOR subscription IN subscriptions
                FILTER subscription.user == @id
                RETURN subscription
        ",
            json!({
            "id": &user.id
        })
        ).await?;

        if subscriptions.len() == 0 {
            let subscription = microsoft::subscribe(
                &session.ms_user,
                "/me/messages?$filter=contains(subject, 'QCM')"
            ).await?;

            db.add("subscriptions", MSSubscription {
                id: subscription.id.clone(),
                user: user.id.clone(),
                expires_at: subscription.expires_at.clone()
            }).await?;

            info!(
                "Registered subscription '{}' expiring at '{}'",
                subscription.id,
                subscription.expires_at
            );
        } else {
            let mut subscription = subscriptions.swap_remove(0);

            if Utc::now() + Duration::hours(2) > subscription.expires_at {
                let expires_at = microsoft::renew_subscription(
                    &session.ms_user,
                    &subscription.id
                ).await?;

                subscription.expires_at = expires_at;

                db.replace("subscriptions", &subscription.id, subscription.clone()).await?;

                info!(
                    "Renewed subscription '{}', now expiring at '{}'",
                    subscription.id,
                    subscription.expires_at
                );
            }
        }
    }

    let qcms = qcm::fetch_qcms(db, user).await?;
    if let Some(qcm) = qcms.get(0) {
        info!("{} new QCMs were received, sending push notification", qcms.len());

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
    } else {
        info!("No new QCM (or first time fetch), not sending a notification");
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
        locks.insert(user.id.clone(), Arc::new(Mutex::new(true)));
    }

    locks.get(&user.id).unwrap().clone()
}

pub async fn get_data(db: &DatabaseConnection, user: &User) -> DataResult<UserData> {
    Ok(UserData {
        admin: get_admin(db, &user.cri_user.promo).await?,
        delegates: get_delegates(db, &user.cri_user.promo).await?,

        next_qcm: qcm::get_next_qcm(db, user).await?,
        qcm_history: qcm::get_qcm_history(db, user).await?,
        mimos: mimos::get_mimos(db, user).await?
    })
}

pub async fn handle_notification(db: &DatabaseConnection, notification: Notification) -> DataResult<()> {
    if &notification.client_state != &CONFIG.ms_webhook_key {
        return Err(DataError::InvalidClientState {
            excepted: CONFIG.ms_webhook_key.clone(),
            returned: notification.client_state.clone()
        });
    }

    // Multiple notifications are sent for each email received, but we must process only one
    if &notification.change_type != "created" {
        return Ok(());
    }

    info!("Received notification id '{}'", notification.id);

    let sub = db.get::<MSSubscription>("subscriptions", &notification.id).await?;
    let user = match sub {
        Some(s) => db.get::<User>("users", &s.user).await?,
        None => None
    };

    if let Some(mut u) = user {
        if let Some(sess) = u.session.as_ref() {
            if Utc::now() > sess.expires_at {
                warn!("User session expired");
            } else {
                info!("Matching user is '{} {}'", u.cri_user.first_name, u.cri_user.last_name);

                if let Err(e) = refresh_user(db, &mut u).await {
                    error!("Failed refreshing after notification : {}", e.to_detailed_string());
                }
            }
        } else {
            warn!("User is not logged");
        }
    } else {
        warn!("No matching user");
    }

    // We de not return an error to not panic MS APIs
    Ok(())
}

pub async fn remove_subscriptions_for(db: &DatabaseConnection, user: &User) -> DataResult<()> {
    let subscriptions: Vec<MSSubscription> = db.single_query(
        r"
            FOR subscription IN subscriptions
                FILTER subscription.user == @id
                RETURN subscription
        ",
        json!({
            "id": &user.id
        })
    ).await?;

    let session = user.session.as_ref().ok_or(DataError::NotLogged)?;

    for subscription in subscriptions {
        microsoft::unsubscribe(&session.ms_user, &subscription.id).await?;
        db.remove("subscriptions", &subscription.id).await?;

        info!("Removing subscription '{}'", subscription.id);
    }

    Ok(())
}

pub async fn notify_all(db: &DatabaseConnection, caller: &User, message: &str) -> DataResult<()> {
    let users: Vec<User> = db.single_query(
        r"
            FOR user IN users
                FILTER user.cri_user.promo == @promo
                FILTER user.session != null
                FILTER user.session.expires_at > @time
                RETURN user
        ",
        json!({
            "promo": &caller.cri_user.promo,
            "time": Utc::now().timestamp()
        })
    ).await?;

    let user_count = users.len();

    for user in users {
        push_notif::notify(
            &user,
            &format!("Alerte de '{} {}'", caller.cri_user.first_name, caller.cri_user.last_name),
            message
        ).await?;
    }

    info!(
        "User '{} {}' sent global notification to '{}' users of promo '{}' with content : '{}'",
        caller.cri_user.first_name,
        caller.cri_user.last_name,
        user_count,
        caller.cri_user.promo,
        message
    );

    Ok(())
}

pub struct RefreshActor {
    pub db: DatabaseConnection
}

impl Actor for RefreshActor {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        info!("Started refresh process (every {} seconds)", REFRESH_RATE);

        ctx.run_interval(StdDuration::from_secs(REFRESH_RATE), move |a, ctx| {
            // We must do this for the reference to be borrowed in the async context
            async fn do_refresh(db: DatabaseConnection) {
                refresh_all(&db).await
            }

            ctx.spawn(actix::fut::wrap_future::<_, Self>(do_refresh(a.db.clone())));
        });
    }
}

#[derive(Fail, Debug)]
pub enum DataError {
    #[fail(display = "Database request failed : {}", error)]
    DatabaseError {
        error: DatabaseError
    },

    #[fail(display = "You must be logged to do this")]
    NotLogged,

    #[fail(display = "Microsoft request failed : {}", error)]
    MSError {
        error: MSError
    },

    #[fail(display = "QCM PDF parsing error : {}", error)]
    PDFError {
        error: PDFError
    },

    #[fail(display = "Invalid regex : {}", error)]
    RegexError {
        error: regex::Error
    },

    #[fail(display = "Invalid QCM subject '{}'", subject)]
    InvalidSubjectError {
        subject: String,
        error: String
    },

    #[fail(display = "Failed to parse date '{}'", date)]
    DateParsingError {
        date: String,
        error: chrono::ParseError
    },

    #[fail(display = "HTTP error while submitting a push notification")]
    PushNotifError {
        error: reqwest::Error
    },

    #[fail(display = "Unable to read request payload")]
    PayloadReadingError {
        error: actix_http::error::PayloadError
    },

    #[fail(display = "Unable to decode request payload as a string")]
    PayloadDecodingError {
        error: std::str::Utf8Error
    },

    #[fail(display = "Unable to decode request payload as json")]
    JsonParsingError {
        payload: String,
        error: serde_json::Error
    },

    #[fail(display = "Client state does not correspond")]
    InvalidClientState {
        excepted: String,
        returned: String
    },

    #[fail(display = "{}", error)]
    UserError {
        error: UserError
    },

    #[fail(display = "You don't have the required privileges to do that")]
    Unauthorized,

    #[fail(display = "Can't find any user with email '{}'", email)]
    UnknownUser {
        email: String
    },

    #[fail(display = "The given entry '{}' already exists in the database", entry)]
    DuplicatedEntry {
        entry: String
    }
}

impl DataError {
    pub fn to_detailed_string(&self) -> String {
        use DataError::*;

        let mut result = String::new();
        result += &self.to_string();

        match self {
            DatabaseError { error } => {
                result = error.to_detailed_string();
            },
            MSError { error } => {
                result = error.to_detailed_string();
            },
            DateParsingError { error, .. } => {
                result += &format!(", chrono dropped error '{}'", error);
            },
            PushNotifError { error } => {
                result += &format!(", reqwest dropped error : '{}'", error);
            },
            PayloadReadingError { error }=> {
                result += &format!(", actix dropped error : '{}'", error);
            },
            PayloadDecodingError { error } => {
                result += &format!(", an UTF-8 error was dropped : '{}'", error);
            },
            JsonParsingError { error, payload} => {
                result += &format!(". Serde dropped error '{}' for payload :\n{}", error, payload);
            },
            InvalidClientState { excepted, returned } => {
                result += &format!(".\nExcepted : '{}'\nReceived : '{}'", excepted, returned);
            },
            UserError { error } => {
                result = error.to_detailed_string()
            },
            _ => {}
        }

        result
    }
}

from_error!(DatabaseError, DataError, DataError::DatabaseError);
from_error!(MSError, DataError, DataError::MSError);
from_error!(PDFError, DataError, DataError::PDFError);
from_error!(UserError, DataError, DataError::UserError);
from_error!(actix_http::error::PayloadError, DataError, DataError::PayloadReadingError);
from_error!(std::str::Utf8Error, DataError, DataError::PayloadDecodingError);
from_error!(regex::Error, DataError, DataError::RegexError);