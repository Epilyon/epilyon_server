use chrono::{DateTime, Utc};
use serde::Serialize;

pub mod cri;
pub mod microsoft;

#[derive(Clone)]
pub struct AuthSession {
    state: AuthState,
    nonce: String,
    identity: Option<AuthIdentity>,
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

    pub fn fail(&mut self) {
        self.state = AuthState::Failed
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
    Failed
}

#[derive(Serialize, Clone)]
pub struct AuthIdentity {
    name: String,
    email: String,
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

#[derive(Debug)]
pub enum AuthError {
    MissingMSVars,
    RemoteError
}