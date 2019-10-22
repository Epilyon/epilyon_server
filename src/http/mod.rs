use std::fmt;
use std::error::Error;

use rocket::request::Request;
use rocket::response::{Response, Responder};
use rocket::http::Status;

use crate::database::DatabaseAccess;
use crate::users::UserManager;

mod auth;

pub fn start(users: UserManager) {
    rocket::ignite()
        .mount("/", routes![
            auth::start,
            auth::login,
            auth::redirect,
            auth::end,
            auth::refresh,
            auth::logout
        ])
        .register(catchers![
            not_found,
            forbidden,
            form_error,
            unknown_error
        ])
        .manage(DatabaseAccess::new())
        .manage(users)
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
            DatabaseError => "Database connection error, this is bad : report this to the server hoster"
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
        "message": format!("Can't find route '{} {}'", req.method(), req.uri().path())
    }).respond_to(req)
}

#[catch(403)]
fn forbidden<'r>(req: &Request) -> Result<Response<'r>, Status> {
    json!({
        "error": "Unauthorized",
        "message": format!("You aren't allowed to do this")
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
