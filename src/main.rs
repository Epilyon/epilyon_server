#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use] extern crate rocket;
#[macro_use] extern crate rocket_contrib;
#[macro_use] extern crate log;
extern crate pretty_env_logger;
extern crate serde;
extern crate serde_derive;
extern crate serde_json;
extern crate chrono;
extern crate time;
extern crate uuid;
extern crate dotenv;
extern crate reqwest;
extern crate jsonwebtoken as jwt;
extern crate base64;

mod http;
mod database;
mod users;
mod refresh;
mod sync;
mod error;

use crate::users::{StateManager, LoggedUser, UserManager};
use crate::database::DatabaseAccess;
use crate::sync::{Asyncable, EpiLock};
use crate::error::EpiError;

// TODO: Log thing more (using debug!)

const VERSION: &'static str = "0.1.0";

fn main() {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", format!("warn,epilyon_server={},launch=info", if std::env::var("EPILYON_DEBUG").is_ok() { "debug" } else { "info" }));
    }

    pretty_env_logger::init();

    info!("Starting Epilyon server v{}", VERSION);
    info!("by Adrien 'Litarvan' Navratil");
    info!("---------------------------------------------------");

    if let Err(e) = dotenv::dotenv() {
        error!("Couldn't load the .env file (did you copy the .env.example file ?) : {}", e);
        return;
    }

    let mut users = UserManager::new();

    info!("Loading users from CRI...");
    if let Err(e) = users::load_users(&mut users) {
        error!("Error while loading users from CRI : {}", e);
        error!("Can't start");

        return;
    }

    info!("Successfully loaded {} users from CRI", users.count());

    // This is meant to be used in the get_users function or passed to schedule_refresh
    // Because they will all be moved to a new scope, we need to do a copy for those passed to Rocket HTTP
    let users = UserManager::new_async(users);
    let db = DatabaseAccess::new_async(DatabaseAccess::new());
    let states = StateManager::new_async(StateManager::new());

    // Those ones will be passed to the HTTP State
    // Cloning an Arc does not clone its content, but makes a new Arc pointing at the same reference
    // arc.clone() is the same as Arc::new(&arc)
    let http_users = users.clone();
    let http_db = db.clone();
    let http_states = states.clone();

    refresh::schedule_refresh(states, move || {
        match db.epilock().get_auth_sessions() {
            Ok(sessions) => {
                let mut result = Vec::new();

                for session in sessions {
                    let users = users.epilock(); // Can't be inline, we must declare it here so it lives for the whole scope
                    let user = users.get_from_session(&session);

                    if let Some(u) = user { // If user is None, it means the session is created but not logged
                        result.push(LoggedUser {
                            user: u.clone(),
                            session
                        });
                    }
                }

                Ok(result)
            },
            Err(e) => {
                error!("Database error while getting sessions for refresh process : {}", e);
                Err(EpiError::DatabaseError)
            }
        }
    });

    info!("Started refresh service");
    info!("Starting HTTP server");

    http::start(http_db, http_users, http_states);
}
