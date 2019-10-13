#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use] extern crate rocket;
#[macro_use] extern crate rocket_contrib;
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

fn main() {
    dotenv::dotenv().ok();
    http::start();
}
