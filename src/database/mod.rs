use std::{fmt, error};
use std::sync::Mutex;
use std::collections::HashMap;

use crate::users::auth::AuthSession;

mod arango;

type Result<T> = std::result::Result<T, DatabaseError>;

pub struct DatabaseAccess {
    sessions: Mutex<HashMap<String, AuthSession>> // TODO: ArangoDB
}

impl DatabaseAccess {
    pub fn new() -> DatabaseAccess {
        DatabaseAccess {
            sessions: Mutex::new(HashMap::<String, AuthSession>::new()) // TODO: ArangoDB xd
        }
    }

    pub fn add_auth_session(&self, id: String, session: AuthSession) -> Result<Option<AuthSession>> {
        match self.sessions.lock() {
            Ok(ref mut map) => {
                Ok(map.insert(id, session))
            },
            Err(_) => Err(DatabaseError::PoisonedMutex)
        }
    }

    pub fn get_auth_session(&self, id: &str) -> Result<Option<AuthSession>> {
        match self.sessions.lock() {
            Ok(ref map) => Ok(map.get(id).map(|s| s.clone())),
            Err(_) => Err(DatabaseError::PoisonedMutex)
        }
    }

    pub fn update_auth_session(&self, id: String, session: AuthSession) -> Result<Option<AuthSession>> {
        self.add_auth_session(id, session)
    }

    pub fn remove_auth_session(&self, id: &str) -> Result<()> {
        match self.sessions.lock() {
            Ok(ref mut map) => {
                map.remove(id);
                Ok(())
            },
            Err(_) => Err(DatabaseError::PoisonedMutex)
        }
    }
}

#[derive(Debug, Clone)]
pub enum DatabaseError {
    ConnectionFailure,
    SetupError,
    PoisonedMutex,
    // TODO: ArangoError
}

impl fmt::Display for DatabaseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use DatabaseError::*;

        write!(f, "{}", match self {
            ConnectionFailure => "Database connection failure",
            SetupError => "Database setup mistake",
            PoisonedMutex => "Another thread panicked during database task execution, mutex is poisoned"
            // TODO: ArangoError
        })
    }
}

impl error::Error for DatabaseError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None // TODO: Arango error if there's one
    }
}