use std::fmt;
use std::error::Error;

use chrono::{DateTime, Utc};
use serde::Serialize;

pub mod cri;
pub mod microsoft;

#[derive(Clone)]
pub struct AuthSession {
    state: AuthState,
    nonce: String,
    identity: Option<AuthIdentity>, // 'Some' if AuthState = Ended | Logged
    created_at: DateTime<Utc>
}

impl AuthSession {
    pub fn new(nonce: String) -> AuthSession {
        AuthSession {
            state: AuthState::Started,
            nonce,
            identity: None,
            created_at: Utc::now()
        }
    }

    pub fn state(&self) -> &AuthState {
        &self.state
    }

    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    pub fn created_at(&self) -> &DateTime<Utc> {
        &self.created_at
    }

    pub fn login(&mut self, identity: AuthIdentity) -> Result<(), ()> {
        if self.state != AuthState::Started {
            return Err(());
        }

        self.identity = Some(identity);
        self.state = AuthState::Ended;

        Ok(())
    }

    pub fn fail(&mut self, err: AuthError) {
        self.state = AuthState::Failed(err)
    }

    pub fn get_identity(&self) -> Option<AuthIdentity> {
        self.identity.clone()
    }
}

#[derive(Clone, PartialEq)]
pub enum AuthState {
    Started,
    Ended,
    Logged,
    Failed(AuthError)
}

#[derive(Serialize, Clone)]
pub struct AuthIdentity {
    pub name: String,
    pub email: String,
    access_token: String,
    refresh_token: String,
    refreshed_at: DateTime<Utc>
}

impl AuthIdentity {
    pub fn new(name: String, email: String, access_token: String, refresh_token: String) -> AuthIdentity {
        AuthIdentity {
            name,
            email,
            access_token,
            refresh_token,
            refreshed_at: Utc::now()
        }
    }
}

#[derive(PartialEq, Clone, Debug)]
pub enum AuthError {
    MissingMSVars,
    RemoteError,
    AlreadyLogged,
    UnknownState,
    DatabaseError // We do not pass database error beacuse it should not be displayed to the user
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use AuthError::*;

        // TODO: Lang? Client-side?
        write!(f, "{}", match self {
            MissingMSVars => "Server setup error : Missing one of the MS .env var (did you copy the .env.example to .env ?)",
            RemoteError => "Remote server (e.g. Microsoft) threw an error, this is bad : report this to the devs",
            AlreadyLogged => "You already went through the auth process, please try again",
            UnknownState => "Can't find out who you are (session expired?) please try again",
            DatabaseError => "Database connection error, this is bad : report this to the server hoster"
        })
    }
}

impl Error for AuthError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}