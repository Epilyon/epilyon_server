use rocket::{State, Request};
use rocket::http::{ContentType, Cookies, Cookie, Status};
use rocket::request::{FromRequest, Outcome, Form};
use rocket::response::{Content, Response, Redirect, Responder};
use rocket_contrib::json::{JsonValue, Json};
use uuid::Uuid;

use crate::auth::{AuthSession, AuthIdentity, AuthState, AuthError};
use crate::auth::microsoft;
use crate::database::DatabaseAccess;
use crate::http::HttpError;

// TODO: Split those in src/auth/mod.rs

#[get("/auth/start")] // TODO: Use POST
pub fn start(db: State<DatabaseAccess>, mut cookies: Cookies) -> Result<JsonValue, HttpError> {
    let state = gen_uuid();
    let session = AuthSession::new(gen_uuid());

    if let Err(e) = db.add_auth_session(state.clone(), session) {
        error!("Database error while adding session '{}' to database : {}", &state, e);
        return Err(HttpError::DatabaseError);
    }

    cookies.add_private(Cookie::new("state", state.clone()));

    // TODO: Rate limiting

    Ok(json!({
        "state_id": state
    }))
}

#[get("/auth/login")]
pub fn login(session: AuthSession, mut cookies: Cookies) -> Result<Redirect, AuthError> {
    // Cookie is unwrapped, because if it wasn't present the AuthSession FromRequest impl would have dropped an error
    let uri = microsoft::get_redirect_uri( cookies.get_private("state").unwrap().value(), session.nonce())?;
    Ok(Redirect::found(uri))
}

#[post("/auth/redirect", data = "<result>")]
pub fn redirect(db: State<DatabaseAccess>, result: Form<LoginResult>) -> Result<Content<&'static str>, AuthError> {
    // TODO: Looks like Cookie isn't passed to the request, did not happen on POC, invest that... (currently getting state from ms, a bit insecure?)

    let db_result = db.get_auth_session(&result.state);

    if let Err(e) = db_result {
        error!("Database error while getting session '{}' to database : {}", &result.state, e);
        return Err(AuthError::DatabaseError);
    }

    let session_opt = db_result.unwrap();

    if session_opt.is_none() {
        warn!("/auth/redirect called with unknown state '{}'", &result.state);
        return Err(AuthError::UnknownState);
    }

    let mut session = session_opt.unwrap();

    match session.state() {
        AuthState::Started => {},
        AuthState::Failed(_) => {
            warn!("/auth/redirect called from a failed session '{}'", &result.state);
            return Err(AuthError::AlreadyLogged);
        } ,
        AuthState::Ended | AuthState::Logged => {
            warn!("/auth/redirect called by a logged user '{}'", &session.get_identity().unwrap().name);
            return Err(AuthError::AlreadyLogged);
        }
    }

    let token = microsoft::acquire_token(&result.code);

    // TODO: Better states (expiration plz)

    match token {
        Ok(identity) => {
            // Can't fail, we already checked the auth state
            let _ = session.login(identity); // let _ suppresses the warning, we already checked the state
            let identity = session.get_identity().unwrap(); // I have to get the identity from here, because it was moved to the session

            match db.update_auth_session(result.state.clone(), session.clone()) {
                Ok(()) => {
                    info!("Successfully logged user '{}' ({})", &identity.name, &identity.email);
                },
                Err(e) => {
                    error!("Database error while updating auth session to log user '{}' : {}", &identity.name, e);
                    session.fail(AuthError::DatabaseError);
                }
            }
        },
        Err(e) => {
            error!("Error acquiring auth tokens for state '{}' : {}", &result.state, e);
            session.fail(e);
        }
    }

    Ok(Content(ContentType::HTML, "I must find a way to close this from the client app... anyway, you're logged <script>window.close();</script>"))
}

#[get("/auth/end")] // TODO: Use POST
pub fn end(session: AuthSession) -> Result<Json<AuthIdentity>, HttpError> {
    match session.state() { // TODO: Manage to use a if?
        &AuthState::Ended => {},
        _ => {
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
                Err(e) => {
                    error!("Database error while loading auth session '{}' : {}", cookie.value(), e);
                    return Outcome::Failure((Status::InternalServerError, HttpError::DatabaseError))
                }
            }
        }

        Outcome::Failure((Status::Forbidden, HttpError::Unauthorized))
    }
}

impl<'r> Responder<'r> for AuthError {
    fn respond_to(self, req: &Request) -> Result<Response<'r>, Status> {
        json!({
            "error": "Authentication error",
            "message": format!("{}", self)
        }).respond_to(req)
    }
}