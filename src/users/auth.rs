use chrono::{DateTime, Utc};
use time::Duration;

use crate::users::UserManager;
use crate::error::{EpiResult, EpiError};

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

    pub fn identify(&mut self, users: &UserManager, email: &str, access_token: String, refresh_token: String, expires_in: usize) -> EpiResult<()> {
        if self.state != AuthState::Started {
            return Err(EpiError::InvalidState);
        }

        let user = users.get_by_email(email);

        if user.is_none() {
            return Err(EpiError::UnknownUser);
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

    pub fn log(&mut self) -> EpiResult<()> {
        if self.state != AuthState::Ended {
            return Err(EpiError::InvalidState);
        }

        self.state = AuthState::Logged;

        Ok(())
    }

    pub fn fail(&mut self, err: EpiError) {
        self.state = AuthState::Failed(err)
    }

    pub fn state(&self) -> &AuthState {
        &self.state
    }

    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    pub fn identity(&self) -> Option<&AuthIdentity> {
        self.identity.as_ref()
    }
}

#[derive(Clone, PartialEq)]
pub enum AuthState {
    Started,
    Ended,
    Logged,
    Failed(EpiError)
}

#[derive(Clone)]
pub struct AuthIdentity {
    user: usize,
    access_token: String,
    refresh_token: String,
    expires_at: DateTime<Utc>
}

impl AuthIdentity {
    pub fn access_token(&self) -> &str {
        &self.access_token
    }
}