mod auth;
pub mod jwt;

use crate::database::DatabaseAccess;

pub fn start() {
    rocket::ignite().mount("/", routes![
        auth::start,
        auth::login,
        auth::redirect,
        auth::end
    ])
        .manage(DatabaseAccess::new())
        .launch();
}

// TODO: Implement this better
#[derive(Debug)]
pub enum HttpError {
    Unauthorized,
    InternalError
}

// TODO: Catchers