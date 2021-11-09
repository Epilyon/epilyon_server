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
use chrono::{DateTime, Utc, NaiveDate, Datelike, NaiveTime, Weekday, Timelike, Date};
use serde::{Serialize, Deserialize};

use crate::db::DatabaseConnection;
use crate::user::{User, microsoft};
use crate::user::microsoft::{MSError, Mail, MSUser};

use super::{pdf, DataResult, DataError};

pub async fn fetch_mcqs(db: &DatabaseConnection, user: &User) -> DataResult<Vec<MCQResult>> {
    let session = user.session.as_ref().ok_or(DataError::NotLogged)?;
    let history_result = db.get::<MCQHistory>("mcq_histories", &user.id).await?;
    let (mut history, is_first_fetch) = match history_result {
        Some(h) => (h, false),
        None => (MCQHistory { promo: user.id.clone(), mcqs: Vec::new() }, true)
    };

    info!("Current MCQ history has {} MCQs in it", history.mcqs.len());

    history.mcqs.sort_by(|a, b| a.date.cmp(&b.date).reverse());

    let mut starting_at = String::from("2020-10-01"); // Before that is the seminar
    if let Some(mcq) = history.mcqs.get(0) {
        let starting_date = mcq.date;
        starting_at = format!(
            "{}-{:02}-{:02}",
            starting_date.year(), starting_date.month(), starting_date.day()
        );
    }

    info!("Fetching MCQ mails since date '{}'", starting_at);

    let mails = microsoft::get_mails(
        &session.ms_user,
        &format!("receivedDateTime gt {} and \
        startsWith(subject, '[EPITA] Résultat du QCM') and hasAttachments eq true", starting_at),
        if history.mcqs.len() == 0 { 50 } else { 6 }
    ).await?;

    info!("Got {} mails", mails.len());

    let mut mcqs: HashMap<String, MCQResult> = HashMap::new();
    for mail in mails {
        match get_date(&mail) {
            Ok((date_key, naive_date)) => {
                if history.mcqs.iter().find(|s| {
                    s.date == naive_date && s.grades.len() == 7
                }).is_some() {
                    info!("MCQ of date '{}' is already completed, skipping", date_key);
                    continue;
                }

                let mcq = fetch_mcq(
                    date_key, naive_date,
                    user, &session.ms_user,
                    &mail,
                    &mut mcqs
                ).await;

                if let Err(e) = mcq {
                    error!("Failed to parse MCQ from mail '{}' : {}", mail.subject, e.to_detailed_string());
                    error!("Skipping this mail");
                }
            },
            Err(e) => {
                error!("Failed to parse mail : {}", e.to_detailed_string());
                error!("Skipping this mail");
            }
        }
    }

    let mut new_mcqs: Vec<MCQResult> = Vec::new();
    for (_, v) in mcqs {
        if !is_first_fetch {
            new_mcqs.push(v.clone());
        }

        history.mcqs.push(v);
    }

    if is_first_fetch {
        db.add("mcq_histories", history).await?;
    } else {
        db.replace("mcq_histories", &history.promo, history.clone()).await?;
    }

    Ok(new_mcqs)
}

fn get_date(mail: &Mail) -> DataResult<(String, NaiveDate)> {
    let mcq_date = regex::Regex::new(r"\d?\d/\d\d")?
        .captures(&mail.subject)
        .and_then(|c| c.get(0))
        .map(|c| c.as_str().to_string())
        .ok_or(DataError::InvalidSubjectError {
            subject: mail.subject.clone(),
            error: "No date was found".into()
        })? + "/" + &mail.received_at.year().to_string();

    let naive_date = NaiveDate::parse_from_str(&mcq_date, "%d/%m/%Y")
        .map_err(|e| DataError::DateParsingError {
            date: mcq_date.to_owned(),
            error: e
        })?;

    let date_key = format!(
        "{}-{:02}-{:02}",
        naive_date.year(), naive_date.month(), naive_date.day()
    );

    Ok((date_key, naive_date))
}

async fn fetch_mcq(
    date_key: String,
    date: NaiveDate,

    user: &User,
    ms_user: &MSUser,

    mail: &Mail,

    mcqs: &mut HashMap<String, MCQResult>
) -> DataResult<()> {
    info!("Parsing mail '{}'", mail.subject);

    let is_first_part = !mail.subject.contains("Feuille 2") && !mail.subject.contains("2ème partie");
    let pts = microsoft::get_first_attachment(
        ms_user,
        &mail,
        "contentType eq 'application/pdf' and name eq 'corrected.pdf'"
    ).await?
        .ok_or(DataError::MissingAttachment { mail: mail.subject.clone() })
        .and_then(|pdf| base64::decode(&pdf.content_bytes)
        .map_err(|e| MSError::ContentDecodingError { error: e }.into()))
        .and_then(|b64| pdf::parse_mcq(b64.as_slice()).map_err(|e| e.into()))?;

    if !mcqs.get(&date_key).is_some() {
        mcqs.insert(date_key.clone(), MCQResult {
            date: date.clone(),
            average: 0.0,
            grades: Vec::new()
        });
    }

    // Always true
    if let Some(mcq) = mcqs.get_mut(&date_key) {
        if mcq.grades.len() == 7 {
            mcqs.remove(&date_key);
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

            "2026" if date_key == "2021-10-11" || date_key == "2021-10-18" => if is_first_part {
                vec!["Algo.", "Mathématiques", "Anglais C.I.E.", "Anglais T.I.M.", "Physique/Élec"]
            } else {
                vec!["blank-part", "Archi."]
            },

            "2026" => if is_first_part {
                vec!["Algo.", "Mathématiques", "Anglais C.I.E.", "Anglais T.I.M.", "Physique/Élec"]
            } else {
                vec!["NTS", "Archi."]
            },

            _ => vec![]
        };

        let shift = if is_first_part { 0 } else { 5 };
        for (i, subject) in subjects.iter().enumerate() {
            if subject == &"blank-part" { continue; }
            let mut points: Vec<f32> = Vec::new();
            for k in (i * 10)..((i+1) * 10) {
                if let Some(pt) = pts.get(k) {
                    points.push(*pt);
                }
            }

            mcq.grades.insert((shift + i).min(mcq.grades.len()), Grade {
                subject: subject.to_string(),
                points
            });
        }

        let mut total_n = 0.0;
        let mut total_d = 0.0;
        for x in mcq.grades.iter() {
            let total: f32 = x.points.iter().sum();
            let coef = match x.subject.as_str() {
                "Algo." => 2.0,
                "Mathématiques" => 3.0,
                "Anglais" => 3.0,
                "Anglais C.I.E." => 1.5,
                "Anglais T.I.M." => 1.5,
                "Physique" => 2.0,
                "Physique/Élec" => 2.0,
                "NTS" => 2.0,
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

        mcq.average = (total_n / total_d) * 20.0;

        info!("MCQ now has '{}' grades", mcq.grades.len());
    }

    Ok(())
}

pub async fn set_next_mcq(
    db: &DatabaseConnection,

    author: &User,

    at: NaiveTime,
    revisions: Vec<Revision>
) -> DataResult<()> {
    let date = get_next_mcq_day().and_time(at);
    match date {
        Some(at) => Ok(db.add_or_replace("next_mcqs", NextMCQ {
            promo: author.cri_user.promo.clone(),

            skipped: false,
            at,
            revisions,
            last_editor: format!("{}", author)
        }).await?),
        None => Err(DataError::InvalidDate { date: at })
    }
}

pub async fn skip_next_mcq(db: &DatabaseConnection, author: &User) -> DataResult<()> {
    Ok(db.add_or_replace("next_mcqs", NextMCQ {
        promo: author.cri_user.promo.clone(),

        skipped: true,
        at: get_next_mcq_day().and_hms(0, 0, 0),
        revisions: Vec::new(),
        last_editor: format!("{}", author)
    }).await?)
}

pub async fn get_next_mcq(db: &DatabaseConnection, user: &User) -> DataResult<Option<NextMCQ>> {
    if let Some(next) = db.get::<NextMCQ>("next_mcqs", &user.cri_user.promo).await? {
        if Utc::now() + Duration::hours(2) <= next.at {
            return Ok(Some(next))
        }

        db.remove("next_mcqs", &next.promo).await?;
    }

    Ok(None)
}

fn get_next_mcq_day() -> Date<Utc> {
    let mut day = Utc::today();
    if day.weekday() == Weekday::Mon {
        if Utc::now().hour() >= 12 {
            return day + Duration::weeks(1);
        }
    }

    while day.weekday() != Weekday::Mon {
        day = day + Duration::days(1);
    }

    day
}

pub async fn get_mcq_history(db: &DatabaseConnection, user: &User) -> DataResult<Vec<MCQResult>> {
    let history: Option<MCQHistory> = db.get("mcq_histories", &user.id).await?;

    Ok(match history {
        Some(h) => h.mcqs,
        None => Vec::new()
    })
}

#[derive(Serialize, Deserialize)]
pub struct NextMCQ {
    #[serde(rename = "_key")]
    promo: String,
    skipped: bool,
    at: DateTime<Utc>,
    revisions: Vec<Revision>,
    last_editor: String
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Revision {
    subject: String,
    work: Vec<String>
}

#[derive(Serialize, Deserialize, Clone)]
pub struct MCQHistory {
    #[serde(rename = "_key")]
    promo: String,
    mcqs: Vec<MCQResult>
}

#[derive(Serialize, Deserialize, Clone)]
pub struct MCQResult {
    pub date: NaiveDate,
    average: f32,
    pub grades: Vec<Grade>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Grade {
    subject: String,
    points: Vec<f32>
}