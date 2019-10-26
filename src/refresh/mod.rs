mod pdf;

use std::thread;
use std::time::Duration;
use std::collections::HashMap;
use std::ops::Range;

use chrono::NaiveDate;

use crate::users::{LoggedUser, StateManager};
use crate::users::state::{QCMResult, UserState};
use crate::users::microsoft;
use crate::sync::{AsyncObj, EpiLock};
use crate::error::{EpiResult, EpiError};

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
    })
}

fn refresh_user(user: &LoggedUser) -> EpiResult<UserState> {
    let last_qcm = get_last_qcm(user)?;

    // TODO: Send notification if last_mail_id id != previous last_qcm.last_mail_id

    Ok(UserState {
       last_qcm
    })
}

fn get_last_qcm(user: &LoggedUser) -> EpiResult<Option<QCMResult>> {
    // User is logged so has he an identity
    // TODO: Move somewhere else
    let identity = user.session.identity().unwrap();

    let mut mails = microsoft::get_mails(identity, "startsWith(subject, '[EPITA] Résultat du QCM') and hasAttachments eq true")?;
    mails.sort_by(|a, b| a.receivedDateTime.cmp(&b.receivedDateTime).reverse());

    if mails.len() == 0 {
        return Ok(None);
    }

    // TODO: Don't parse if same mail id as previous last_qcm.last_mail_id

    let mut result: HashMap<String, f32> = HashMap::new();
    let mut date: Option<NaiveDate> = None;

    for i in 0..2 {
        let mail = mails.get(i);

        if mail.is_none() {
            continue;
        }

        let mail = mail.unwrap();

        if date.is_none() {
            match NaiveDate::parse_from_str(&mail.subject[28..38], "%d/%m/%Y") { // '[EPITA] Résultat du QCM du '.len() = 27, 'XX/XX/XXXX'.len() = 10
                Ok(d) => {
                    date = Some(d);
                },
                Err(e) => {
                    error!("Error while parsing QCM Date from mail subject '{}' : {}", mail.subject, e);
                    return Err(EpiError::RemoteError);
                }
            }
        }

        let pdf = microsoft::get_first_attachment(identity, mail, "contentType eq 'application/pdf' and name eq 'corrected.pdf'")?;

        if pdf.is_none() {
            continue;
        }

        let b64 = base64::decode(&pdf.unwrap().contentBytes);

        if let Err(e) = b64 {
            error!("Error while decoding base64 of mail attachment data : {}", e);
            return Err(EpiError::RemoteError);
        }

        match pdf::parse_qcm(b64.unwrap().as_slice()) {
            Ok(pts) => {
                let f = |r: Range<u8>| r.fold(0f32, |sum, x| sum + pts.get(x as usize).unwrap());

                if mail.subject.contains("Part 2") {
                    if pts.len() < 20 {
                        error!("Part 2 of QCM '{}' had not 20 questions but {}, can't parse", mail.subject, pts.len());
                        return Err(EpiError::RemoteError);
                    }

                    result.insert("Electronique".into(), f(0..10)); // TODO: Move subjects names somewhere else
                    result.insert("Architecture".into(), f(10..20));
                } else {
                    if pts.len() < 50 {
                        error!("Part 1 of QCM '{}' had not 50 questions but {}, can't parse", mail.subject, pts.len());
                        return Err(EpiError::RemoteError);
                    }

                    result.insert("Algorithmique".into(), f(0..10));
                    result.insert("Mathématiques".into(), f(10..20));
                    result.insert("Anglais CIE".into(), f(20..30));
                    result.insert("Anglais TIM".into(), f(30..40));
                    result.insert("Physique".into(), f(40..50));

                    break; // If last QCM is Part 1, Part 2 is not out yet so we don't need to search for it
                }
            },
            Err(e) => {
                error!("Error while parsing QCM PDF : {}", e);
                return Err(EpiError::RemoteError);
            }
        }
    }

    if date.is_none() {
        // The only way for this to happen is that a mail was found matching the name but with no PDF attached
        warn!("Invalid QCM mail was trying to be parsed : '{}'", mails.get(0).unwrap().subject);
        return Ok(None);
    }

    Ok(Some(QCMResult {
        last_mail: mails.get(0).unwrap().id.clone(),
        date: date.unwrap(),
        values: result
    })) // TODO: ...
}
