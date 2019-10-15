#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use] extern crate rocket;
#[macro_use] extern crate rocket_contrib;
#[macro_use] extern crate log;
extern crate pretty_env_logger;
extern crate serde;
extern crate serde_derive;
extern crate serde_json;
extern crate chrono;
extern crate uuid;
extern crate dotenv;
extern crate reqwest;
extern crate base64;

mod http;
mod database;
mod auth;
mod users;

const VERSION: &'static str = "1.0.0";

fn main() {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "warn,epilyon_server=info,launch=info");
    }

    pretty_env_logger::init();

    info!("Starting Epilyon server v{}", VERSION);
    info!("by Adrien 'Litarvan' Navratil");
    info!("---------------------------------------------------");

    dotenv::dotenv().ok();

    info!("Loading users from CRI...");
    match users::load_users() {
        Ok(users) => {
            info!("Successfully loaded {} users from CRI", users.count());
            info!("Starting HTTP server");

            http::start(users);
        },
        Err(e) => {
            error!("Error while loading users from CRI : {}", e);
            error!("Can't start");
        }
    }
}
