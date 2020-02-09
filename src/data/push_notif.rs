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
use serde_json::json;

use crate::config::CONFIG;
use crate::user::User;
use crate::data::DataError;

pub async fn notify(user: &User, title: &str, message: &str) -> Result<(), DataError> {
    let device_token = &user.session.as_ref().ok_or(DataError::NotLogged)?.device_token;

    reqwest::Client::new().post("https://fcm.googleapis.com/fcm/send")
        .header("Authorization", format!("key={}", CONFIG.firebase_secret))
        .json(&json!({
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
        }))
        .send().await.map_err(|e| DataError::PushNotifError { error: e })?;

    Ok(())
}