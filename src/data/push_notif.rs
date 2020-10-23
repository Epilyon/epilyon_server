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
use serde_json::json;
use chrono::Utc;

use crate::config::CONFIG;
use crate::user::User;
use crate::data::{DataError, DataResult};
use crate::db::DatabaseConnection;

pub async fn notify_all(db: &DatabaseConnection, caller: &User, message: &str) -> DataResult<()> {
    let users: Vec<User> = db.single_query(
        r"
            FOR user IN users
                FILTER user.cri_user.promo == @promo
                FILTER user.session != null
                FILTER user.session.expires_at > @time
                RETURN user
        ",
        json!({
            "promo": &caller.cri_user.promo,
            "time": Utc::now().timestamp()
        })
    ).await?;

    for user in &users {
        notify(
            user,
            &format!("Alerte de '{} {}'", caller.cri_user.first_name, caller.cri_user.last_name),
            message
        ).await?;
    }

    info!(
        "User '{} {}' sent global notification to '{}' users of promo '{}' with content : '{}'",
        caller.cri_user.first_name,
        caller.cri_user.last_name,
        users.len(),
        caller.cri_user.promo,
        message
    );

    Ok(())
}

pub async fn notify(user: &User, title: &str, message: &str) -> Result<(), DataError> {
    let device_token = &user.session.as_ref().ok_or(DataError::NotLogged)?.device_token;
    let body = json!({
        "notification": {
            "title": title,
            "body": message
        },
        "proprity": "high",
        "data": {
            "id": "1",
            "status": "done",
            "click_action": "FLUTTER_NOTIFICATION_CLICK"
        },
        "to": device_token
    });

    reqwest::Client::new().post("https://fcm.googleapis.com/fcm/send")
        .header("Authorization", format!("key={}", CONFIG.firebase_secret))
        .json(&body)
        .send().await.map_err(|e| DataError::PushNotifError { error: e })?;

    Ok(())
}