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
use log::info;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};

use crate::db::DatabaseConnection;
use crate::data::{DataResult, DataError};
use crate::user::User;

#[derive(Serialize, Deserialize)]
struct PromoMimos {
    #[serde(rename = "_key")]
    promo: String,
    mimos: Vec<Mimos>
}

#[derive(Serialize, Deserialize)]
pub struct Mimos {
    subject: String,
    number: u8,
    title: String,
    date: DateTime<Utc>
}

pub async fn get_mimos(db: &DatabaseConnection, user: &User) -> DataResult<Vec<Mimos>> {
    let all = get_promos_mimos(db, user).await?;
    Ok(all.mimos)
}

pub async fn add_mimos(db: &DatabaseConnection, user: &User, mimos: Mimos) -> DataResult<()> {
    let mut all = get_promos_mimos(db, user).await?;
    if all.mimos.iter().any(|m| m.number == mimos.number && m.subject == mimos.subject) {
        return Err(DataError::DuplicatedEntry {
            entry: format!("Mimos number '{}' of subject '{}'", mimos.number, mimos.subject)
        });
    }

    all.mimos.push(mimos);
    db.replace("mimos", &all.promo.clone(), all).await?;

    info!(
        "User '{} {}' added new Mimos for subject '{}' : '{} - {}' for {}",
        user.cri_user.first_name,
        user.cri_user.last_name,
        mimos.subject,
        mimos.number,
        mimos.title,
        mimos.date.to_rfc2822()
    );

    Ok(())
}

pub async fn remove_mimos(db: &DatabaseConnection, user: &User, number: u8, subject: &str) -> DataResult<()> {
    let mut all = get_promos_mimos(db, user).await?;
    all.mimos = all.mimos
        .into_iter()
        .filter(|m| m.number != number || m.subject != subject)
        .collect();

    db.replace("mimos", &all.promo.clone(), all).await?;

    info!(
        "User '{} {}' removed Mimos number '{}' of subject '{}'",
        user.cri_user.first_name,
        user.cri_user.last_name,
        number,
        subject
    );

    Ok(())
}

async fn get_promos_mimos(db: &DatabaseConnection, user: &User) -> DataResult<PromoMimos> {
    match db.get::<PromoMimos>("mimos", &user.cri_user.promo).await? {
        Some(m) => Ok(m),
        None => {
            let mimos = PromoMimos {
                promo: user.cri_user.promo.clone(),
                mimos: Vec::new()
            };

            db.add("mimos", &mimos).await?;

            Ok(mimos)
        }
    }
}