use rocket::request::Request;
use rocket::response::{Response, Responder};
use rocket::http::{Status, Header};
use rocket::fairing::{Fairing, Info, Kind};

use crate::database::DatabaseAccess;
use crate::users::{UserManager, StateManager};
use crate::sync::AsyncObj;
use crate::error::EpiError;

mod auth;
mod state;

pub fn start(db: AsyncObj<DatabaseAccess>, users: AsyncObj<UserManager>, states: AsyncObj<StateManager>) {
    rocket::ignite()
        .mount("/", routes![
            auth::start,
            auth::login,
            auth::redirect,
            auth::end,
            auth::refresh,
            auth::logout,

            state::get
        ])
        .register(catchers![
            not_found,
            forbidden,
            form_error,
            unknown_error
        ])
        .manage(db)
        .manage(users)
        .manage(states)
        .attach(UTF8Responder {})
        .launch();
}

impl<'r> Responder<'r> for EpiError {
    fn respond_to(self, req: &Request) -> Result<Response<'r>, Status> {
        json!({
            "error": "General error",
            "message": format!("{}", self)
        }).respond_to(req)
    }
}

struct UTF8Responder;

impl Fairing for UTF8Responder {
    fn info(&self) -> Info {
        Info {
            name: "UTF-8 Responder",
            kind: Kind::Response
        }
    }

    fn on_response(&self, _request: &Request, response: &mut Response) {
        let header = response.headers().get_one("Content-Type");

        if header.is_some() && header.unwrap() == "application/json" {
            response.set_header(Header::new("Content-Type", "application/json; charset=utf-8"));
        }
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
