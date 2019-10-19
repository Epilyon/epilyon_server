use rocket::{State, Request};
use rocket::http::{ContentType, Status};
use rocket::request::{FromRequest, Outcome, Form};
use rocket::response::{Content, Response, Redirect, Responder};
use rocket_contrib::json::JsonValue;
use uuid::Uuid;
use jwt::{Header as JwtHeader, Validation};
use chrono::Utc;
use time::Duration;
use serde::{Deserialize, Serialize};

use crate::users::auth::{AuthSession, AuthState, AuthError};
use crate::users::{User, microsoft, UserManager};
use crate::database::DatabaseAccess;
use crate::http::HttpError;

#[post("/auth/start")]
pub fn start(db: State<DatabaseAccess>) -> Result<JsonValue, AuthError> {
    let state = gen_uuid();
    let session = AuthSession::new(gen_uuid());

    let secret = get_auth_secret()?;

    if let Err(e) = db.add_auth_session(state.clone(), session) {
        error!("Database error while adding session '{}' to database : {}", &state, e);
        return Err(AuthError::DatabaseError);
    }

    let claims = TokenClaims {
        sub: state,
        iss: "Epilyon".into(),
        exp: (Utc::now() + Duration::days(14)).timestamp()
    };

    // TODO: Rate limiting

    match jwt::encode(&JwtHeader::default(), &claims, secret.as_ref()) {
        Ok(token) => Ok(json!({
            "token": token
        })),
        Err(e) => {
            error!("Error while generating JWT for session '{}' : {}", &claims.sub, e);
            Err(AuthError::TokenError)
        }
    }
}

#[get("/auth/login")]
pub fn login(session: AuthSession, claims: TokenClaims) -> Result<Redirect, AuthError> {
    // Cookie is unwrapped, because if it wasn't present the AuthSession FromRequest impl would have dropped an error
    let uri = microsoft::get_redirect_uri( &claims.sub, session.nonce())?;
    Ok(Redirect::found(uri))
}

#[post("/auth/redirect", data = "<result>")]
pub fn redirect(db: State<DatabaseAccess>, users: State<UserManager>, result: Form<LoginResult>) -> Result<Content<&'static str>, AuthError> {
    let db_result = db.get_auth_session(&result.state);

    if let Err(e) = db_result {
        error!("Database error while getting session '{}' to database : {}", &result.state, e);
        return Err(AuthError::DatabaseError);
    }

    let session_opt = db_result.unwrap();

    if session_opt.is_none() {
        warn!("/auth/redirect called with unknown state '{}'", &result.state);
        return Err(AuthError::UnknownSession);
    }

    let mut session = session_opt.unwrap();

    match session.state() {
        AuthState::Started => {},
        AuthState::Failed(_) => {
            warn!("/auth/redirect called from a failed session '{}'", &result.state);
            return Err(AuthError::InvalidState);
        },
        AuthState::Ended | AuthState::Logged => {
            warn!("/auth/redirect called by a logged user '{}'", &users.get_from_session(&session).unwrap().email);
            return Err(AuthError::InvalidState);
        }
    }

    microsoft::identify(&mut session, users.inner(), &result.code)?;

    let user = users.get_from_session(&session).unwrap();

    match db.update_auth_session(result.state.clone(), session.clone()) {
        Ok(_) => {
            info!("Successfully logged user '{} {}' ({})", &user.first_name, &user.last_name, &user.email);
        },
        Err(e) => {
            error!("Database error while updating auth session to log user '{}' : {}", &user.email, e);
            session.fail(AuthError::DatabaseError);
        }
    }

    Ok(Content(ContentType::HTML, "<script>if (Epilyon) { Epilyon.postMessage('Close') }</script>")) // TODO: Move somewhere
}

#[post("/auth/end")]
pub fn end(users: State<UserManager>, session: AuthSession) -> Result<JsonValue, HttpError> {
    match session.state() { // TODO: Manage to use a if?
        &AuthState::Ended => match users.get_from_session(&session) {
            Some(user) => Ok(json!({
                "id": &user.uid,
                "name": format!("{} {}", &user.first_name, &user.last_name),
                "email": &user.email,
                "promo": &user.promo,
                "region": &user.region
            })),
            None => {
                error!("User session '{}' has no user associated with", session.user().unwrap());
                Err(HttpError::Unauthorized)
            },
        },
        _ => Err(HttpError::Unauthorized)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenClaims {
    sub: String,
    iss: String,
    exp: i64
}

#[derive(FromForm)]
pub struct LoginResult {
    code: String,
    state: String,
    #[allow(dead_code)]
    session_state: String // Needed for Rocket to parse the response
}

fn get_auth_secret() -> Result<String, AuthError> {
    std::env::var("AUTH_SECRET").map_err(|_| AuthError::MissingSecret)
}

fn gen_uuid() -> String {
    Uuid::new_v4().to_hyphenated().to_string()
}

impl<'a, 'r> FromRequest<'a, 'r> for TokenClaims {
    type Error = HttpError;

    fn from_request(request: &'a Request<'r>) -> Outcome<TokenClaims, HttpError> {
        let auth = request.headers().get_one("Authorization");

        if let Some(content) = auth {
            let split: Vec<_> = content.split_ascii_whitespace().collect();

            if let Some(token) = split.get(1) {
                if let Ok(secret) = get_auth_secret() {
                    if let Ok(result) = jwt::decode::<TokenClaims>(token, secret.as_ref(), &Validation::default()) {
                        return Outcome::Success(result.claims.clone()); // TODO: Is there a better way ?
                    }
                }
            }
        }

        Outcome::Failure((Status::Forbidden, HttpError::Unauthorized))
    }
}

impl<'a, 'r> FromRequest<'a, 'r> for AuthSession {
    type Error = HttpError;

    fn from_request(request: &'a Request<'r>) -> Outcome<AuthSession, HttpError> {
        let db = request.guard::<State<DatabaseAccess>>().unwrap(); // Can't fail
        let token = TokenClaims::from_request(request);

        if let Outcome::Success(claims) = token {
            match db.get_auth_session(&claims.sub) {
                Ok(opt) => if let Some(sess) = opt {
                    return Outcome::Success(sess)
                },
                Err(e) => {
                    error!("Database error while loading auth session '{}' : {}", &claims.sub, e);
                    return Outcome::Failure((Status::InternalServerError, HttpError::DatabaseError))
                }
            }
        }

        Outcome::Failure((Status::Forbidden, HttpError::Unauthorized))
    }
}

impl<'a, 'r> FromRequest<'a, 'r> for User {
    type Error = HttpError;

    fn from_request(request: &'a Request<'r>) -> Outcome<User, HttpError> {
        let session = AuthSession::from_request(request)?;
        let users = request.guard::<State<UserManager>>().unwrap(); // Can't fail

        // TODO: Check tokens expiration

        match users.get_from_session(&session) {
            Some(u) => Outcome::Success(u.clone()),
            None => Outcome::Failure((Status::Forbidden, HttpError::Unauthorized))
        }
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


// TODO: Refresh
