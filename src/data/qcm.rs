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
use std::ops::Range;

use time::Duration;
use chrono::{DateTime, Utc, NaiveDate, Datelike};
use serde::{Serialize, Deserialize};
use serde_json::json;

use crate::db::DatabaseConnection;
use crate::user::{User, microsoft};
use crate::user::microsoft::MSError;

use super::pdf;
use super::DataError;

pub async fn fetch_qcms(db: &DatabaseConnection, user: &User) -> Result<Vec<QCMResult>, DataError> {
    let session = user.session.as_ref().ok_or(DataError::NotLogged)?;
    let mut history_result = db.single_query::<Vec<QCMHistory>>(
        r"
            FOR history IN qcm_histories
                FILTER history.user == @user
                RETURN history
        ",
        json!({
            "user": &user.id
        })
    ).await?;

    let mut history = if history_result.len() > 0 {
        history_result.swap_remove(0)
    } else {
        QCMHistory {
            _key: "".into(),
            user: user.id,
            qcms: Vec::new()
        }
    };

    history.qcms.sort_by(|a, b| a.date.cmp(&b.date).reverse());

    let mut starting_at = String::from("2019-10-01"); // Before that is the seminar
    if let Some(qcm) = history.qcms.get(0) {
        let starting_date = qcm.date;
        starting_at = format!("{}-{:02}-{:02}", starting_date.year(), starting_date.month(), starting_date.day());
    }

    let mails = microsoft::get_mails(
        &session.ms_user,
        &format!("receivedDateTime gt {} and \
        startsWith(subject, '[EPITA] Résultat du QCM') and hasAttachments eq true", starting_at),
        if history.qcms.len() == 0 { 50 } else { 6 }
    ).await?;

    let mut qcms: HashMap<&str, QCMResult> = HashMap::new();

    for mail in mails.iter() {
        let date = &mail.subject[28..38];
        let naive_date = NaiveDate::parse_from_str(date, "%d/%m/%Y")?;

        if history.qcms.iter().find(|s| s.date == naive_date).is_some() {
            continue;
        }

        let pdf = microsoft::get_first_attachment(
            &session.ms_user,
            &mail,
            "contentType eq 'application/pdf' and name eq 'corrected.pdf'"
        ).await?;

        if pdf.is_none() {
            continue;
        }

        let b64: Vec<u8> = base64::decode(&pdf.unwrap().contentBytes)
            .map_err(|e| MSError::ContentDecodingError { error: e })?;
        let pts = pdf::parse_qcm(b64.as_slice())?;

        let f = |r: Range<u8>| {
            let mut result: Vec<f32> = Vec::new();
            for i in r {
                if let Some(pt) = pts.get(i as usize) {
                    result.push(*pt);
                }
            }

            result
        };

        let is_first_part = !mail.subject.contains("Part 2");

        if !qcms.contains_key(date) {
            qcms.insert(date, QCMResult {
                date: naive_date.clone(),
                average: 0.0,
                grades: Vec::new()
            });
        }

        // Always true
        if let Some(qcm) = qcms.get_mut(date) {
            if qcm.grades.len() == 7 {
                qcms.remove(date);
                continue;
            }

            if is_first_part {
                qcm.grades.push(Grade { subject: "Algo.".into(),         points: f(0..10)  });
                qcm.grades.push(Grade { subject: "Mathématiques".into(), points: f(10..20) });
                qcm.grades.push(Grade { subject: "Anglais CIE".into(),   points: f(20..30) });
                qcm.grades.push(Grade { subject: "Anglais TIM".into(),   points: f(30..40) });
                qcm.grades.push(Grade { subject: "Physique".into(),      points: f(40..50) });
            } else {
                qcm.grades.push(Grade { subject: "Élec.".into(),         points: f(0..10)  });
                qcm.grades.push(Grade { subject: "Architecture".into(),  points: f(10..20) });
            }

            let mut total_n = 0.0;
            let mut total_d = 0.0;
            for x in qcm.grades.iter() {
                let total: f32 = x.points.iter().sum();
                let coef = match x.subject.as_str() {
                    "Algo." => 2.0,
                    "Mathématiques" => 3.0,
                    "Anglais CIE" => 1.5,
                    "Anglais TIM" => 1.5,
                    "Physique" => 2.0,
                    "Élec" => 2.0,
                    "Architecture" => 2.0,
                    _ => 0.0
                };

                total_n += total * coef;
                total_d += 10.0 * coef;
            }

            qcm.average = (total_n / total_d) * 20.0;
        }
    }

    let mut new_qcms: Vec<QCMResult> = Vec::new();
    for (_, v) in qcms {
        new_qcms.push(v.clone());
        history.qcms.push(v);
    }

    if history._key.as_str() == "" {
        db.add("qcm_histories", json!({
            "user": history.user.clone(),
            "qcms": history.qcms.clone()
        })).await?;
    } else {
        db.replace("qcm_histories", &history._key, history.clone()).await?;
    }

    Ok(new_qcms)
}

pub async fn get_next_qcm(db: &DatabaseConnection, user: &User) -> Result<Option<NextQCM>, DataError> {
    let mut result: Vec<NextQCM> = db.single_query(
        r"
            FOR next IN next_qcms
                FILTER next.promo == @promo
                RETURN next
        ", json!({
            "promo": &user.cri_user.promo
        })
    ).await?;

    Ok(match result.len() {
        0 => None,
        _ => {
            let next = result.swap_remove(0);

            if Utc::now() + Duration::hours(2) > next.at {
                db.remove("next_qcms", &next._key).await?;
                None
            } else {
                Some(next)
            }
        }
    })
}

pub async fn get_qcm_history(db: &DatabaseConnection, user: &User) -> Result<Vec<QCMResult>, DataError> {
    Ok(db.single_query(
        r"
            FOR history IN qcm_histories
                FILTER history.user == @user_id
                FOR qcm IN history.qcms
                    RETURN qcm
        ", json!({
            "user_id": &user.id
        })
    ).await?)
}

#[derive(Serialize, Deserialize)]
pub struct NextQCM {
    _key: String,
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
    _key: String,
    user: u32,
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