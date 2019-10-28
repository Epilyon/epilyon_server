use std::ops::Deref;

use rocket::Request;
use rocket::http::{ContentType, Status};
use rocket::request::{FromRequest, Outcome, Form};
use rocket::response::{Content, Redirect};
use rocket_contrib::json::JsonValue;
use uuid::Uuid;
use jwt::{Header as JwtHeader, Validation};
use chrono::Utc;
use time::Duration;
use serde::{Deserialize, Serialize};

use crate::users::auth::{AuthSession, AuthState};
use crate::users::{microsoft, UserManager, LoggedUser, StateManager};
use crate::database::DatabaseAccess;
use crate::error::{EpiResult, EpiError};
use crate::sync::{AsyncState, EpiLock};
use crate::refresh::refresh as do_refresh;

#[post("/auth/start")]
pub fn start(db: AsyncState<DatabaseAccess>) -> EpiResult<JsonValue> {
    let state = gen_uuid();
    let session = AuthSession::new(gen_uuid());

    if let Err(e) = db.epilock().add_auth_session(state.clone(), session) {
        error!("Database error while adding session '{}' to database : {}", &state, e);
        return Err(EpiError::DatabaseError);
    }

    // TODO: Rate limiting

    Ok(json!({
        "token": gen_token(state)?
    }))
}

#[get("/auth/login")]
pub fn login(session: AuthSession, claims: TokenClaims) -> EpiResult<Redirect> {
    // Cookie is unwrapped, because if it wasn't present the AuthSession FromRequest impl would have dropped an error
    let uri = microsoft::get_redirect_uri( &claims.sub, session.nonce())?;
    Ok(Redirect::found(uri))
}

#[post("/auth/redirect", data = "<result>")]
pub fn redirect(db: AsyncState<DatabaseAccess>, users: AsyncState<UserManager>, result: Form<LoginResult>) -> EpiResult<Content<&'static str>> {
    let db = db.epilock();
    let users = users.epilock();

    let db_result = db.get_auth_session(&result.state);

    if let Err(e) = db_result {
        error!("Database error while getting session '{}' to database : {}", &result.state, e);
        return Err(EpiError::DatabaseError);
    }

    let session_opt = db_result.unwrap();

    if session_opt.is_none() {
        warn!("/auth/redirect called with unknown state '{}'", &result.state);
        return Err(EpiError::UnknownSession);
    }

    let mut session = session_opt.unwrap();

    match session.state() {
        AuthState::Started => {},
        AuthState::Failed(_) => {
            warn!("/auth/redirect called from a failed session '{}'", &result.state);
            return Err(EpiError::InvalidState);
        },
        AuthState::Ended | AuthState::Logged => {
            warn!("/auth/redirect called by a logged user '{}'", &users.get_from_session(&session).unwrap().email);
            return Err(EpiError::InvalidState);
        }
    }

    microsoft::identify(&mut session, users.deref(), &result.code)?;

    let user = users.get_from_session(&session).unwrap();

    match db.update_auth_session(result.state.clone(), session.clone()) {
        Ok(_) => {
            info!("Successfully logged user '{} {}' ({})", &user.first_name, &user.last_name, &user.email);
        },
        Err(e) => {
            error!("Database error while updating auth session to log user '{}' : {}", &user.email, e);
            session.fail(EpiError::DatabaseError);
        }
    }

    Ok(Content(ContentType::HTML, "<script>if (Epilyon) { Epilyon.postMessage('Close') }</script>")) // TODO: Move somewhere
}

#[post("/auth/end")]
pub fn end(users: AsyncState<UserManager>, states: AsyncState<StateManager>, mut session: AuthSession) -> EpiResult<JsonValue> {
    match session.state() {
        &AuthState::Ended | &AuthState::Logged => match users.epilock().get_from_session(&session) {
            Some(user) => {
                let logged = LoggedUser {
                    user: user.clone(),
                    session: session.clone()
                };

                do_refresh(states.inner(), &logged)?;
                session.log()?;

                Ok(json!({
                    "id": &user.uid,
                    "name": format!("{} {}", &user.first_name, &user.last_name),
                    "email": &user.email,
                    "promo": &user.promo,
                    "region": &user.region
                }))
            },
            None => {
                error!("User session '{}' has no user associated with", session.user().unwrap());
                Err(EpiError::Unauthorized)
            },
        },
        _ => Err(EpiError::Unauthorized)
    }
}

#[post("/auth/refresh")]
pub fn refresh(db: AsyncState<DatabaseAccess>, claims: TokenClaims, _user: LoggedUser) -> EpiResult<JsonValue> {
    // TODO: Remove _user: LoggedUser, manage this correctly client-side instead
    // LoggedUser is passed so the whole token check process is went through
    // TODO: Refresh MS connection

    match db.epilock().expire_valider(claims.valider.clone()) {
        Ok(()) => Ok(json!({
            "token": gen_token(claims.sub.clone())?
        })),
        Err(e) => {
            error!("Database error while expiring valider '{}' : {}", &claims.valider, e);
            Err(EpiError::DatabaseError)
        }
    }
}

#[post("/auth/logout")]
pub fn logout(db: AsyncState<DatabaseAccess>, claims: TokenClaims) -> EpiResult<JsonValue> {
    let db = db.epilock();

    db.remove_auth_session(&claims.sub).map_err(|e| {
        error!("Database error while removing auth session '{}' : {}", &claims.sub, e);
        EpiError::DatabaseError
    })?;

    match db.expire_valider(claims.valider.clone()) {
        Ok(()) => Ok(json!({
            "success": true
        })),
        Err(e) => {
            error!("Database error while setting valider '{}' expired : {}", &claims.valider, e);
            Err(EpiError::DatabaseError)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenClaims {
    sub: String,
    iss: String,
    exp: i64,
    valider: String
}

#[derive(FromForm)]
pub struct LoginResult {
    code: String,
    state: String,
    #[allow(dead_code)]
    session_state: String // Needed for Rocket to parse the response
}

fn get_auth_secret() -> EpiResult<String> {
    std::env::var("AUTH_SECRET").map_err(|_| EpiError::MissingVar)
}

fn gen_uuid() -> String {
    Uuid::new_v4().to_hyphenated().to_string()
}

fn gen_token(state: String) -> EpiResult<String> {
    let secret = get_auth_secret()?;

    let claims = TokenClaims {
        sub: state,
        iss: "Epilyon".into(),
        exp: (Utc::now() + Duration::days(14)).timestamp(),
        valider: gen_uuid() // A token that can be invalidated during refresh
    };

    match jwt::encode(&JwtHeader::default(), &claims, secret.as_ref()) {
        Ok(token) => Ok(token),
        Err(e) => {
            error!("Error while generating JWT for session '{}' : {}", &claims.sub, e);
            Err(EpiError::TokenError)
        }
    }
}

impl<'a, 'r> FromRequest<'a, 'r> for TokenClaims {
    type Error = EpiError;

    fn from_request(request: &'a Request<'r>) -> Outcome<TokenClaims, EpiError> {
        let db = request.guard::<AsyncState<DatabaseAccess>>().unwrap(); // Can't fail
        let auth = request.headers().get_one("Authorization");

        if let Some(content) = auth {
            let split: Vec<_> = content.split_ascii_whitespace().collect();

            if let Some(token) = split.get(1) {
                if let Ok(secret) = get_auth_secret() {
                    if let Ok(result) = jwt::decode::<TokenClaims>(token, secret.as_ref(), &Validation::default()) {

                        match db.epilock().is_valider_expired(&result.claims.valider) {
                            Ok(expired) => if !expired {
                                return Outcome::Success(result.claims.clone()); // TODO: Is there a better way ?
                            },
                            Err(e) => {
                                error!("Database errr while checking valider '{}' : {}", &result.claims.valider, e);
                                return Outcome::Failure((Status::InternalServerError, EpiError::DatabaseError));
                            }
                        }
                    }
                }
            }
        }

        Outcome::Failure((Status::Forbidden, EpiError::Unauthorized))
    }
}

impl<'a, 'r> FromRequest<'a, 'r> for AuthSession {
    type Error = EpiError;

    fn from_request(request: &'a Request<'r>) -> Outcome<AuthSession, EpiError> {
        let db = request.guard::<AsyncState<DatabaseAccess>>().unwrap(); // Can't fail
        let token = TokenClaims::from_request(request);

        if let Outcome::Success(claims) = token {
            match db.epilock().get_auth_session(&claims.sub) {
                Ok(opt) => if let Some(sess) = opt {
                    return Outcome::Success(sess)
                },
                Err(e) => {
                    error!("Database error while loading auth session '{}' : {}", &claims.sub, e);
                    return Outcome::Failure((Status::InternalServerError, EpiError::DatabaseError))
                }
            }
        }

        Outcome::Failure((Status::Forbidden, EpiError::Unauthorized))
    }
}

impl<'a, 'r> FromRequest<'a, 'r> for LoggedUser {
    type Error = EpiError;

    fn from_request(request: &'a Request<'r>) -> Outcome<LoggedUser, EpiError> {
        let session = AuthSession::from_request(request)?;
        let users_lock = request.guard::<AsyncState<UserManager>>().unwrap(); // Can't fail
        let users = users_lock.epilock(); // Needed so both users_lock and users live for the whole function

        match users.get_from_session(&session) {
            Some(u) => Outcome::Success(LoggedUser {
                user: u.clone(),
                session
            }),
            None => Outcome::Failure((Status::Forbidden, EpiError::Unauthorized))
        }
    }
}
