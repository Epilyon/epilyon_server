use std::io::Cursor;

use rocket::{State, Request};
use rocket::http::{ContentType, Cookies, Cookie, Status};
use rocket::request::{FromRequest, Outcome, Form};
use rocket::response::{Response, Redirect, Responder};
use rocket_contrib::json::{JsonValue, Json};
use uuid::Uuid;

use crate::auth::{AuthSession, AuthIdentity, AuthState, AuthError};
use crate::auth::microsoft;
use crate::database::DatabaseAccess;
use crate::http::HttpError;

// TODO: Split those in src/auth/mod.rs

#[get("/auth/start")]
pub fn start(db: State<DatabaseAccess>, mut cookies: Cookies) -> JsonValue {
    let state = gen_uuid();
    let session = AuthSession::new(gen_uuid());

    db.add_auth_session(state.clone(), session); // TODO: Check this
    cookies.add_private(Cookie::new("state", state.clone()));

    // TODO: Rate limiting

    json!({
        "state_id": state
    })
}

#[get("/auth/login")]
pub fn login(session: AuthSession, mut cookies: Cookies) -> Result<Redirect, AuthError> {
    // Cookie is unwrapped, because if it wasn't present the AuthSession FromRequest impl would have dropped an error
    let uri = microsoft::get_redirect_uri( cookies.get_private("state").unwrap().value(), session.nonce())?;
    Ok(Redirect::found(uri))
}

#[post("/auth/redirect", data = "<result>")]
pub fn redirect(db: State<DatabaseAccess>, result: Form<LoginResult>) -> &'static str {
    // TODO: Looks like Cookie isn't passed to the request, did not happen on POC, invest that... (currently getting state from ms, a bit insecure?)

    // TODO: Manage those results in a better way ?
    let db_result = db.get_auth_session(&result.state);

    println!("State: '{}'", &result.state);

    if db_result.is_err() {
        println!("DB error"); // TODO: Delete those debug messages (and use a logger ffs)
        return "Database error"; // TODO: Manage error correctly (how?)
    }

    let session_opt = db_result.unwrap();

    if session_opt.is_none() {
        println!("state error");
        return "Unauthorized"; // TODO: ...
    }

    let mut session = session_opt.unwrap();
    if !AuthState::Started.eq(session.state()) {
        return "Already logged"; // TODO: ...
    }

    let token = microsoft::acquire_token(&result.code);

    // TODO: Better states (expiration plz)

    match token {
        Ok(identity) => {
            // Can't fail, we already checked the auth state
            let _ = session.login(identity); // let _ suppresses the warning
            db.update_auth_session(result.state.clone(), session.clone()); // TODO: Check this
        },
        Err(e) => {
            // TODO: Log error ? + Repeat??
            println!("Failure");
            session.fail();
        }
    }

    "<script>window.close();</script>"
}

#[get("/auth/end")]
pub fn end(session: AuthSession) -> Result<Json<AuthIdentity>, HttpError> {
    match session.state() { // TODO: Manage to use a if
        &AuthState::Ended => {},
        _ => {
            // TODO: Send out auth error + proper http error (responder?)
            return Err(HttpError::Unauthorized)
        }
    }

    match session.get_identity() {
        Some(id) => Ok(Json(id)),
        None => Err(HttpError::Unauthorized),
    }
}

#[derive(FromForm)]
pub struct LoginResult {
    code: String,
    state: String,
    #[allow(dead_code)]
    session_state: String // Needed for Rocket to parse the response
}

fn gen_uuid() -> String {
    Uuid::new_v4().to_hyphenated().to_string()
}

impl<'a, 'r> FromRequest<'a, 'r> for AuthSession {
    type Error = HttpError;

    fn from_request(request: &'a Request<'r>) -> Outcome<AuthSession, HttpError> {
        let db = request.guard::<State<DatabaseAccess>>().unwrap(); // Can't fail
        let cookie = request.cookies().get_private("state");

        if let Some(cookie) = cookie {
            match db.get_auth_session(cookie.value()) {
                Ok(opt) => if let Some(sess) = opt {
                    return Outcome::Success(sess)
                },
                Err(_) => {
                    return Outcome::Failure((Status::InternalServerError, HttpError::InternalError))
                }
            }
        }

        Outcome::Failure((Status::Forbidden, HttpError::Unauthorized))
    }
}

impl<'r> Responder<'r> for AuthError {
    fn respond_to(self, _request: &Request) -> Result<Response<'r>, Status> {
        // TODO: Trace error!

        Response::build()
            .header(ContentType::JSON)
            .sized_body(Cursor::new("{ \"error\": \"oh no auth error\" }")) // TODO: Send it for real
            .ok() // TODO: Change response code
    }
}