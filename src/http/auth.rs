/*
 * Epilyon, keeping EPITA students organized
 * Copyright (C) 2019-2020 Adrien 'Litarvan' Navratil
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
use std::collections::HashMap;
use std::sync::Mutex;

use log::{info, warn, error};
use failure::Fail;
use lazy_static::lazy_static;
use chrono::{DateTime, Utc};
use uuid::Uuid;
use time::Duration;
use serde_json::json;
use serde::Deserialize;
use futures::future::{ok, err, Ready};
use actix_web::{
    get, post,
    web,
    HttpRequest, HttpResponse,
    FromRequest, Responder,
    dev::Payload, dev::HttpResponseBuilder,
    http::StatusCode,
    ResponseError
};

use crate::sync::EpiLock;
use crate::user::{microsoft, UserError, UserSession, User, cri::CRIUser};
use crate::user::admins::{has_admin_infos, add_promo_infos};
use crate::db::{DatabaseConnection, DatabaseError};
use crate::data::remove_subscriptions_for;

const AUTH_SESSION_DURATION: i64 = 10 * 60 * 1000; // Ten minutes
const USER_SESSION_DURATION: i64 = 2 * 7 * 24 * 60 * 60 * 1000; // Two weeks

lazy_static! {
    static ref BASE_STATE: web::Data<AuthState> = web::Data::new(AuthState {
        sessions: Mutex::new(HashMap::new()),
    });
}

pub struct AuthState {
    sessions: Mutex<HashMap<String, AuthSession>>
}

#[derive(Clone)]
pub struct AuthSession {
    state: String,
    nonce: String,
    device_token: String,
    expires_at: DateTime<Utc>,
    result: Option<(String, CRIUser)>,
}

pub fn configure(cfg: &mut web::ServiceConfig, db: web::Data<DatabaseConnection>) {
    cfg.service(
        web::scope("/")
            .app_data(BASE_STATE.clone())
            .app_data(db)
            .service(start)
            .service(login)
            .service(redirect)
            .service(end)
            .service(refresh)
            .service(logout)
    );
}

#[post("/start")]
pub async fn start(state: web::Data<AuthState>, info: web::Json<StartQuery>) -> impl Responder {
    // TODO: Rate limit this
    let token = gen_uuid();

    state.sessions.epilock().insert(token.clone(), AuthSession {
        state: token.clone(),
        nonce: gen_uuid(),
        device_token: info.device_token.clone(),
        expires_at: Utc::now() + Duration::milliseconds(AUTH_SESSION_DURATION),
        result: None
    });

    HttpResponse::Ok().json(json!({
        "success": true,
        "token": token
    }))
}

#[get("/login")]
pub async fn login(session: AuthSession) -> impl Responder {
    HttpResponse::Found()
        .set_header("Location", microsoft::get_redirect_uri(&session.state, &session.nonce))
        .finish()
}

#[post("/redirect")]
pub async fn redirect(
    state: web::Data<AuthState>,
    db: web::Data<DatabaseConnection>,
    result: web::Form<LoginResult>
)-> Result<HttpResponse, AuthError> {
    let mut sessions = state.sessions.epilock(); // So the lock lives for the whole function
    let session = sessions.get_session(&result.state)
        .ok_or(AuthError::InvalidState { token: result.state.clone() })?;

    let (email, ms_user) = microsoft::identify(&result.code, &session.nonce).await?;

    let mut matches: Vec<User> = db.single_query(
        r"
            FOR user IN users
                FILTER user.cri_user.email == @email
                    RETURN user
        ", json!({
            "email": email
        })
    ).await?;

    if matches.len() == 0 {
        return Err(AuthError::UnknownUser {
            email: email.clone()
        });
    }

    let mut user = matches.swap_remove(0);
    user.session = Some(UserSession {
        token: result.state.clone(),
        ms_user,
        expires_at: Utc::now() + Duration::milliseconds(USER_SESSION_DURATION),
        device_token: session.device_token.clone()
    });

    if !has_admin_infos(db.as_ref(), &user.cri_user.promo).await? {
        add_promo_infos(db.as_ref(), &user).await?;

        info!(
            "'{} {}' is the first of the promo '{}' to log in, making them its administrator",
            user.cri_user.first_name,
            user.cri_user.last_name,
            user.cri_user.promo
        );
    }

    db.replace("users", &user.id, user.clone()).await?;

    session.result = Some((user.id.clone(), user.cri_user.clone()));

    info!(
        "Successfully logged user {} {} ({})",
        user.cri_user.first_name,
        user.cri_user.last_name,
        user.cri_user.email
    );

    Ok(HttpResponse::Ok()
        .content_type("text/html")
        .body("<script>if (Epilyon) { Epilyon.postMessage('Close') }</script>"))
}

#[post("/end")]
pub async fn end(
    state: web::Data<AuthState>,
    db: web::Data<DatabaseConnection>,
    session: AuthSession
) -> Result<HttpResponse, AuthError> {
    match &session.result {
        Some((id, user)) => {
            let mut sessions = state.sessions.epilock();
            sessions.remove(&session.state);

            let first = db.single_query::<Vec<bool>>(
                r"
                    FOR history IN qcm_histories
                        FILTER history.user == @user
                        return true
                ",
                json!({
                    "user": id
                })
            ).await?;


            Ok(HttpResponse::Ok().json(json!({
                "success": true,
                "user": user,
                "first_time": first.len() == 0
            })))
        },
        None => Err(AuthError::AuthCancelled)
    }
}

#[post("/refresh")]
pub async fn refresh(mut user: User, db: web::Data<DatabaseConnection>) -> Result<HttpResponse, AuthError> {
    let new_token = gen_uuid();
    if let Some(ref mut s) = user.session { // Always true
        s.token = new_token.clone();
        s.expires_at = Utc::now() + Duration::milliseconds(USER_SESSION_DURATION);
    }

    db.replace("users", &user.id, user.clone()).await?;

    Ok(HttpResponse::Ok().json(json!({
        "success": true,
        "token": new_token,
        "user": user.cri_user.clone()
    })))
}

#[post("/logout")]
pub async fn logout(mut user: User, db: web::Data<DatabaseConnection>) -> Result<HttpResponse, AuthError> {
    user.session = None;

    info!("Logging out user '{} {}'", user.cri_user.first_name, user.cri_user.last_name);

    if let Err(e) = remove_subscriptions_for(db.get_ref(), &user).await {
        warn!("Couldn't remove user subscriptions : {}", e.to_detailed_string());
        warn!("Ignoring");
    }

    db.replace("users", &user.id, user.clone()).await?;

    Ok(HttpResponse::Ok().json(json!({
        "success": true
    })))
}

fn gen_uuid() -> String {
    Uuid::new_v4().to_hyphenated().to_string()
}

fn get_token(req: &HttpRequest) -> Result<String, AuthError> {
    Ok(String::from(req.headers().get("Token")
        .ok_or(AuthError::MissingToken)?
        .to_str().map_err(|_| AuthError::InvalidTokenFormat)?))
}

trait SessionContainer {
    fn get_session(&mut self, token: &str) -> Option<&mut AuthSession>;
}

impl SessionContainer for HashMap<String, AuthSession> {
    fn get_session(&mut self, token: &str) -> Option<&mut AuthSession> {
        let now = Utc::now();
        self.retain(|_, s| s.expires_at > now);

        self.get_mut(token)
    }
}

#[derive(Deserialize)]
pub struct StartQuery {
    device_token: String
}

#[derive(Deserialize)]
pub struct LoginResult {
    code: String,
    state: String
}

impl FromRequest for AuthSession {
    type Error = AuthError;
    type Future = Ready<Result<Self, Self::Error>>;
    type Config = ();

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        // We need to use ok/err from 'futures' as traits still can't have async functions, so
        // to make this simpler I did a Result wrapper to be able to use '?'
        fn get_session(req: &HttpRequest) -> Result<Option<AuthSession>, AuthError> {
            let data = req.app_data::<web::Data<AuthState>>()
                .ok_or(AuthError::ServiceError)?;
            let mut sessions = data.sessions.epilock();
            let token = get_token(req)?;

            Ok(sessions.get_session(&token).map(|s| s.clone()))
        }

        match get_session(req) {
            Ok(sess) => match sess {
                Some(s) => ok(s.clone()),
                None => err(AuthError::InvalidToken {
                    token: get_token(req).unwrap_or(String::from("(unknown token)"))
                })
            },
            Err(e) => err(e)
        }
    }
}

impl FromRequest for User {
    type Error = AuthError;
    // Again, traits cannot have async function, but we need to use db.single_query which return
    // a dynamic Future. But, the Future type we response must be sized, that's why we must use
    // a Box. As it needs to be 'Unpin', we use Box::pin, which makes this type :
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self, Self::Error>>>>;
    type Config = ();

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        async fn get_user(req: HttpRequest) -> Result<User, AuthError> {
            let token = get_token(&req)?;
            let db = req.app_data::<web::Data<DatabaseConnection>>()
                .ok_or(AuthError::ServiceError)?;

            let mut matches: Vec<User> = db.single_query(
                r"
                    FOR user IN users
                        FILTER user.session.token == @token
                            RETURN user
                ",
                json!({
                    "token": &token
                })
            ).await?;

            if matches.len() == 0 {
                Err(AuthError::InvalidToken { token: token.clone() })
            } else {
                let user = matches.swap_remove(0);

                if match &user.session {
                    Some(s) => Utc::now() > s.expires_at,
                    None => true
                } {
                    Err(AuthError::InvalidToken { token: token.clone() })
                } else {
                    Ok(user)
                }
            }
        }

        Box::pin(get_user(req.clone()))
    }
}

#[derive(Debug, Fail)]
pub enum AuthError {
    #[fail(display = "Invalid or expired token")]
    InvalidToken {
        token: String
    },

    #[fail(display = "Given token is not valid UTF-8")]
    InvalidTokenFormat,

    #[fail(display = "Missing 'Token' header in the request")]
    MissingToken,

    #[fail(display = "Application service misconfiguration")]
    ServiceError,

    #[fail(display = "Unknown state token received")]
    InvalidState {
        token: String
    },

    #[fail(display = "Microsoft API remote error : {}", error)]
    MicrosoftError {
        error: microsoft::MSError
    },

    #[fail(display = "User with email '{}' can't be found in the CRI, \
    are you really from Epita Lyon ?", email)]
    UnknownUser {
        email: String
    },

    #[fail(display = "Database remote error : {}", error)]
    DatabaseError {
        error: DatabaseError
    },

    #[fail(display = "{}", error)]
    UserError {
        error: UserError
    },

    #[fail(display = "Auth process was cancelled or not finished")]
    AuthCancelled
}

impl AuthError {
    fn to_detailed_string(&self) -> String {
        use AuthError::*;

        let mut result = String::new();
        result += &self.to_string();

        match self {
            InvalidToken { token } => {
                result += &format!(" : '{}'.", token);
            },
            ServiceError => {
                result += ". Couldn't retrieve 'AuthState' instance from the request.";
            },
            InvalidState { token } => {
                result += &format!(" : '{}'.", token);
            },
            MicrosoftError { error } => {
                result = format!("Microsoft API remote error : {}", error.to_detailed_string());
            },
            DatabaseError { error } => {
                result = format!("Database remote error : {}", error.to_detailed_string());
            },
            UserError { error } => {
                result = error.to_detailed_string();
            },
            _ => {}
        }

        result
    }
}

impl ResponseError for AuthError {
    fn status_code(&self) -> StatusCode {
        use AuthError::*;

        match self {
            MissingToken | InvalidTokenFormat =>
                StatusCode::BAD_REQUEST,
            InvalidToken { .. } | InvalidState { .. } | AuthCancelled | UnknownUser { .. } =>
                StatusCode::FORBIDDEN,
            ServiceError | MicrosoftError { .. } | UserError { .. } =>
                StatusCode::INTERNAL_SERVER_ERROR,
            DatabaseError { .. } => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }

    fn error_response(&self) -> HttpResponse {
        error!("Auth error dropped during request : {}", self.to_detailed_string());

        HttpResponseBuilder::new(self.status_code()).json(json!({
            "success": false,
            "error": format!("{}", self)
        }))
    }
}

from_error!(microsoft::MSError, AuthError, AuthError::MicrosoftError);
from_error!(DatabaseError, AuthError, AuthError::DatabaseError);
from_error!(UserError, AuthError, AuthError::UserError);
