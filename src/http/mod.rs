use std::fmt;
use std::error::Error;

use rocket::request::Request;
use rocket::response::{Response, Responder};
use rocket::http::Status;

use crate::database::DatabaseAccess;

mod auth;
pub mod jwt;

pub fn start() {
    rocket::ignite()
        .mount("/", routes![
            auth::start,
            auth::login,
            auth::redirect,
            auth::end
        ])
        .register(catchers![
            not_found,
            form_error,
            unknown_error
        ])
        .manage(
            DatabaseAccess::new()
        )
        .launch();
}

#[derive(Debug)]
pub enum HttpError {
    Unauthorized,
    DatabaseError
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use HttpError::*;

        write!(f, "{}", match self {
            Unauthorized => "You must be logged to do that",
            DatabaseError => "Database connection error, this is bad : report this to the server hoster", // TODO: feeling of déjà vu...
        })
    }
}

impl Error for HttpError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

impl<'r> Responder<'r> for HttpError {
    fn respond_to(self, req: &Request) -> Result<Response<'r>, Status> {
        json!({
            "error": "General error",
            "message": format!("{}", self)
        }).respond_to(req)
    }
}

#[catch(404)]
fn not_found<'r>(req: &Request) -> Result<Response<'r>, Status> {
    json!({
        "error": "Not found",
        "message": format!("Can't find route  '{}'", req.uri().path())
    }).respond_to(req)
}

#[catch(422)]
fn form_error<'r>(req: &Request) -> Result<Response<'r>, Status> {
    json!({
        "error": "Malformed request",
        "message": "Malformed form data (missing fields / wrong order)"
    }).respond_to(req)
}

#[catch(500)]
fn unknown_error<'r>(req: &Request) -> Result<Response<'r>, Status> {
    json!({
        "error": "Unknown error",
        "message": "Unknown error, this is bad please report this"
    }).respond_to(req)
}