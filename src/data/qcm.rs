/*
 * Epilyon, keeping EPITA students organized
 * Copyright (C) 2019-2020 Adrien 'Litarvan' Navratil
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
use std::collections::HashMap;

use log::{info, warn, error};
use time::Duration;
use chrono::{DateTime, Utc, NaiveDate, Datelike};
use serde::{Serialize, Deserialize};

use crate::db::DatabaseConnection;
use crate::user::{User, microsoft};
use crate::user::microsoft::{MSError, Mail, MSUser};

use super::{pdf, DataResult, DataError};

pub async fn fetch_qcms(db: &DatabaseConnection, user: &User) -> DataResult<Vec<QCMResult>> {
    let session = user.session.as_ref().ok_or(DataError::NotLogged)?;
    let history_result = db.get::<QCMHistory>("qcm_histories", &user.id).await?;
    let (mut history, is_first_fetch) = match history_result {
        Some(h) => (h, false),
        None => (QCMHistory { promo: user.id.clone(), qcms: Vec::new() }, true)
    };

    info!("Current QCM history has {} QCMs in it", history.qcms.len());

    history.qcms.sort_by(|a, b| a.date.cmp(&b.date).reverse());

    let mut starting_at = String::from("2020-10-01"); // Before that is the seminar
    if let Some(qcm) = history.qcms.get(0) {
        let starting_date = qcm.date;
        starting_at = format!(
            "{}-{:02}-{:02}",
            starting_date.year(), starting_date.month(), starting_date.day()
        );
    }

    info!("Fetching QCM mails since date '{}'", starting_at);

    let mails = microsoft::get_mails(
        &session.ms_user,
        &format!("receivedDateTime gt {} and \
        startsWith(subject, '[EPITA] Résultat du QCM') and hasAttachments eq true", starting_at),
        if history.qcms.len() == 0 { 50 } else { 6 }
    ).await?;

    info!("Got {} mails", mails.len());

    let mut qcms: HashMap<String, QCMResult> = HashMap::new();
    for mail in mails {
        match get_date(&mail.subject) {
            Ok((date_key, naive_date)) => {
                if history.qcms.iter().find(|s| {
                    s.date == naive_date && s.grades.len() == 7
                }).is_some() {
                    info!("QCM of date '{}' is already completed, skipping", date_key);
                    continue;
                }

                let qcm = fetch_qcm(
                    date_key, naive_date,
                    user, &session.ms_user,
                    &mail,
                    &mut qcms
                ).await;

                if let Err(e) = qcm {
                    error!("Failed to parse QCM from mail '{}' : {}", mail.subject, e.to_detailed_string());
                    error!("Skipping this mail");
                }
            },
            Err(e) => {
                error!("Failed to parse mail : {}", e.to_detailed_string());
                error!("Skipping this mail");
            }
        }
    }

    let mut new_qcms: Vec<QCMResult> = Vec::new();
    for (_, v) in qcms {
        if !is_first_fetch {
            new_qcms.push(v.clone());
        }

        history.qcms.push(v);
    }

    if is_first_fetch {
        db.add("qcm_histories", history).await?;
    } else {
        db.replace("qcm_histories", &history.promo, history.clone()).await?;
    }

    Ok(new_qcms)
}

fn get_date(subject: &String) -> DataResult<(String, NaiveDate)> {
    let qcm_date = regex::Regex::new(r"\d?\d/\d\d")?
        .captures(subject)
        .and_then(|c| c.get(0))
        .map(|c| c.as_str().to_string())
        .ok_or(DataError::InvalidSubjectError {
            subject: subject.clone(),
            error: "No date was found".into()
        })? + "/2020";

    let naive_date = NaiveDate::parse_from_str(&qcm_date, "%d/%m/%Y")
        .map_err(|e| DataError::DateParsingError {
            date: qcm_date.to_owned(),
            error: e
        })?;

    let date_key = format!(
        "{}-{:02}-{:02}",
        naive_date.year(), naive_date.month(), naive_date.day()
    );

    Ok((date_key, naive_date))
}

async fn fetch_qcm(
    date_key: String,
    date: NaiveDate,

    user: &User,
    ms_user: &MSUser,

    mail: &Mail,

    qcms: &mut HashMap<String, QCMResult>
) -> DataResult<()> {
    info!("Parsing mail '{}'", mail.subject);

    let pdf = microsoft::get_first_attachment(
        ms_user,
        &mail,
        "contentType eq 'application/pdf' and name eq 'corrected.pdf'"
    ).await?;

    if pdf.is_none() {
        // TODO: Err
        return Ok(());
    }

    let b64: Vec<u8> = base64::decode(&pdf.unwrap().content_bytes)
        .map_err(|e| MSError::ContentDecodingError { error: e })?;
    let pts = pdf::parse_qcm(b64.as_slice())?;
    let is_first_part = !mail.subject.contains("2ème partie");

    if !qcms.get(&date_key).is_some() {
        qcms.insert(date_key.clone(), QCMResult {
            date: date.clone(),
            average: 0.0,
            grades: Vec::new()
        });
    }

    // Always true
    if let Some(qcm) = qcms.get_mut(&date_key) {
        if qcm.grades.len() == 7 {
            qcms.remove(&date_key);
            return Ok(());
        }

        let subjects = match user.cri_user.promo.as_str() {
            // *clown emoji*
            "2024" if date_key == "2020-10-12" => if is_first_part {
                vec!["Algo.", "Mathématiques", "Physique", "Élec.", "Archi."]
            } else {
                vec!["O.C.", "Anglais"]
            },

            "2024" => if is_first_part {
                vec!["Algo.", "Mathématiques", "Anglais", "O.C.", "Physique"]
            } else {
                vec!["Élec.", "Archi."]
            },
            "2025" => if is_first_part {
                vec!["Algo.", "Mathématiques", "Anglais C.I.E.", "Anglais T.I.M.", "Physique"]
            } else {
                vec!["Élec.", "Archi."]
            },

            _ => vec![]
        };

        let shift = if is_first_part { 0 } else { 5 };
        for (i, subject) in subjects.iter().enumerate() {
            let mut points: Vec<f32> = Vec::new();
            for k in i..i+10 {
                if let Some(pt) = pts.get(k) {
                    points.push(*pt);
                }
            }

            qcm.grades.insert(shift + i, Grade { subject: subject.to_string(), points });
        }

        let mut total_n = 0.0;
        let mut total_d = 0.0;
        for x in qcm.grades.iter() {
            let total: f32 = x.points.iter().sum();
            let coef = match x.subject.as_str() {
                "Algo." => 2.0,
                "Mathématiques" => 3.0,
                "Anglais" => 3.0,
                "Anglais C.I.E." => 1.5,
                "Anglais T.I.M." => 1.5,
                "Physique" => 2.0,
                "Élec." => 2.0,
                "Archi." => 2.0,
                "O.C." => 1.0,
                _ => {
                    warn!("Unknown subject '{}', assuming 1.0 coefficient", x.subject);
                    1.0
                }
            };

            total_n += total.max(0.0) * coef;
            total_d += 10.0 * coef;
        }

        qcm.average = (total_n / total_d) * 20.0;

        info!("QCM now has '{}' grades", qcm.grades.len());
    }

    Ok(())
}

pub async fn get_next_qcm(db: &DatabaseConnection, user: &User) -> DataResult<Option<NextQCM>> {
    if let Some(next) = db.get::<NextQCM>("next_qcms", &user.cri_user.promo).await? {
        if Utc::now() + Duration::hours(2) > next.at {
            db.remove("next_qcms", &next.promo).await?;
            Ok(None)
        } else {
            Ok(Some(next))
        }
    } else {
        Ok(None)
    }
}

pub async fn get_qcm_history(db: &DatabaseConnection, user: &User) -> DataResult<Vec<QCMResult>> {
    let history: Option<QCMHistory> = db.get("qcm_histories", &user.id).await?;

    Ok(match history {
        Some(h) => h.qcms,
        None => Vec::new()
    })
}

#[derive(Serialize, Deserialize)]
pub struct NextQCM {
    #[serde(rename = "_key")]
    promo: String,
    skipped: bool,
    at: DateTime<Utc>,
    revisions: Vec<Revision>
}

#[derive(Serialize, Deserialize)]
pub struct Revision {
    subject: String,
    work: Vec<String>
}

#[derive(Serialize, Deserialize, Clone)]
pub struct QCMHistory {
    #[serde(rename = "_key")]
    promo: String,
    qcms: Vec<QCMResult>
}

#[derive(Serialize, Deserialize, Clone)]
pub struct QCMResult {
    pub date: NaiveDate,
    average: f32,
    pub grades: Vec<Grade>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Grade {
    subject: String,
    points: Vec<f32>
}