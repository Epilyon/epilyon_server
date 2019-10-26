use std::thread;
use std::time::Duration;

use crate::users::{LoggedUser, StateManager};
use crate::users::state::{QCMResult, UserState};
use crate::users::microsoft;
use crate::sync::{AsyncObj, EpiLock};
use crate::error::EpiResult;

pub fn schedule_refresh<F: 'static>(states: AsyncObj<StateManager>, get_users: F) where F: Send + Fn() -> EpiResult<Vec<LoggedUser>> {
    thread::spawn(move || loop {
        let result = get_users();
        if result.is_err() {
            error!("Couldn't retrieve users for the refresh process, skipping iteration");
            return;
        }

        let users = result.unwrap();

        debug!("Starting refresh process for {} users...", users.len());

        for user in users.iter() {
            if let Err(e) = refresh(&states, user) {
                error!("Error during refresh, skipping user : {}", e);
            }
        }

        debug!("Successfully refreshed {} users", users.len());
        thread::sleep(Duration::from_secs(300)); // TODO: Move refresh rate in .env
    });
}

pub fn refresh(states: &AsyncObj<StateManager>, user: &LoggedUser) -> EpiResult<()> {
    debug!("Refreshing user '{} {}'...", &user.user.first_name, &user.user.last_name);

    refresh_user(user).map(|state| {
        states.epilock().update(user.user.uid.clone(), state);
        debug!("Successfully refresh user");
    })
}

fn refresh_user(user: &LoggedUser) -> EpiResult<UserState> {
    let last_qcm = get_last_qcm(user)?;

    Ok(UserState {
       last_qcm
    })
}

fn get_last_qcm(user: &LoggedUser) -> EpiResult<Option<QCMResult>> {
    let mails = microsoft::get_mails(user.session.identity().unwrap(), 20)?; // User is logged so has he an identity

    for mail in mails.iter() {
        println!("Mail from '{}' received at '{}' with subject '{}'", &mail.sender.emailAddress.address, &mail.receivedDateTime, &mail.subject);
    }

    Ok(None) // TODO: ...
}
