use std::fmt;
use std::error::Error;

use chrono::{DateTime, Utc};
use crate::users::UserManager;
use time::Duration;

type AuthResult<T> = std::result::Result<T, AuthError>;

#[derive(Clone)]
pub struct AuthSession {
    state: AuthState,
    nonce: String,
    identity: Option<AuthIdentity>, // 'Some' if AuthState = Ended | Logged
    created_at: DateTime<Utc>
}

impl AuthSession {
    pub fn new(nonce: String) -> Self {
        AuthSession {
            state: AuthState::Started,
            nonce,
            identity: None,
            created_at: Utc::now()
        }
    }

    pub fn identify(&mut self, users: &UserManager, email: &str, access_token: String, refresh_token: String, expires_in: usize) -> AuthResult<()> {
        if self.state != AuthState::Started {
            return Err(AuthError::InvalidState);
        }

        let user = users.get_by_email(email);

        if user.is_none() {
            return Err(AuthError::UnknownUser);
        }

        self.state = AuthState::Ended;
        self.identity = Some(AuthIdentity {
            user: user.unwrap().uid,
            access_token,
            refresh_token,
            expires_at: Utc::now() + Duration::milliseconds(expires_in as i64)
        });

        Ok(())
    }

    pub fn user(&self) -> Option<usize> {
        self.identity.as_ref().map(|i| i.user)
    }

    pub fn fail(&mut self, err: AuthError) {
        self.state = AuthState::Failed(err)
    }

    pub fn state(&self) -> &AuthState {
        &self.state
    }

    pub fn nonce(&self) -> &str {
        &self.nonce
    }
}

#[derive(Clone, PartialEq)]
pub enum AuthState {
    Started,
    Ended,
    Logged,
    Failed(AuthError)
}

#[derive(Clone)]
struct AuthIdentity {
    user: usize,
    access_token: String,
    refresh_token: String,
    expires_at: DateTime<Utc>
}

#[derive(PartialEq, Clone, Debug)]
pub enum AuthError {
    MissingMSVars,
    RemoteError,
    InvalidState,
    UnknownSession,
    UnknownUser,
    DatabaseError // We do not pass the database error cause because it should not be displayed to the user
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use AuthError::*;

        // TODO: Lang? Client-side?
        write!(f, "{}", match self {
            MissingMSVars => "Server setup error : Missing one of the MS .env var (did you copy the .env.example to .env ?)",
            RemoteError => "Microsoft API threw an error, this is bad : report this to the devs",
            InvalidState => "Your auth state is invalid for your request (trying to login while already logged ?)",
            UnknownSession => "Can't find out who you are (session expired?) please try again",
            UnknownUser => "Can't find you in the CRI, are you still at the EPITA ? Contact the devs if you are",
            DatabaseError => "Database connection error, this is bad : report this to the server host"
        })
    }
}

impl Error for AuthError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}
