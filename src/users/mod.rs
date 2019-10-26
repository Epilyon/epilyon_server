pub mod microsoft;
pub mod auth;
pub mod state;

mod cri;

pub use cri::load_users;
pub use state::StateManager;

use auth::AuthSession;

#[derive(Clone)]
pub struct User {
    pub uid: usize,
    pub first_name: String,
    pub last_name: String,
    pub email: String,
    pub promo: String,
    pub region: String,
    pub groups: Vec<String>
}

pub struct LoggedUser { // TODO: Use references maybe? Lifetimes aren't that scary
    pub user: User,
    pub session: AuthSession
}

// TODO: Group system
struct Group {
    name: String,
    promo: String,
    region: String
}

pub struct UserManager {
    users: Vec<User>
}

impl UserManager {
    pub fn new() -> Self {
        UserManager {
            users: Vec::new()
        }
    }

    pub fn count(&self) -> usize {
        self.users.len()
    }

    pub fn get_by_email(&self, email: &str) -> Option<&User> {
        self.users.iter().find(|u| u.email == email)
    }

    pub fn get_by_id(&self, id: usize) -> Option<&User> {
        self.users.iter().find(|u| u.uid == id)
    }

    pub fn get_from_session(&self, session: &AuthSession) -> Option<&User> {
        session.user().and_then(|u| self.get_by_id(u))
    }
}