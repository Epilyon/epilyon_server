use crate::auth::AuthSession;

mod cri;

pub use cri::load_users;

struct User {
    uid: usize,
    first_name: String,
    last_name: String,
    email: String,
    promo: String,
    region: String,
    groups: Vec<String>,
    session: Option<AuthSession>
}

struct Group {
    name: String,
    promo: String,
    region: String
}

pub struct UserManager {
    users: Vec<User>
}

impl UserManager {
    fn new() -> Self {
        UserManager {
            users: Vec::new()
        }
    }

    pub fn count(&self) -> usize {
        self.users.len()
    }
}