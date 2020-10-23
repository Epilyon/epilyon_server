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
use log::{info, warn, error};
use chrono::{Duration, Utc};
use serde_json::json;

use crate::config::CONFIG;
use crate::db::DatabaseConnection;
use crate::user::{User, microsoft};
use crate::data::{DataResult, DataError, refresh_user};
use crate::user::microsoft::{MSSubscription, Notification, MSUser};

pub async fn handle_notification(db: &DatabaseConnection, notification: Notification) -> DataResult<()> {
    if &notification.client_state != &CONFIG.ms_webhook_key {
        return Err(DataError::InvalidClientState {
            excepted: CONFIG.ms_webhook_key.clone(),
            returned: notification.client_state.clone()
        });
    }

    // Multiple notifications are sent for each email received, but we must process only one
    if &notification.change_type != "created" {
        return Ok(());
    }

    info!("Received notification id '{}'", notification.id);

    let sub = db.get::<MSSubscription>("subscriptions", &notification.id).await?;
    let user = match sub {
        Some(s) => db.get::<User>("users", &s.user).await?,
        None => None
    };

    if let Some(mut u) = user {
        if let Some(sess) = u.session.as_ref() {
            if Utc::now() > sess.expires_at {
                warn!("User session expired");
            } else {
                info!("Matching user is '{} {}'", u.cri_user.first_name, u.cri_user.last_name);

                if let Err(e) = refresh_user(db, &mut u).await {
                    error!("Failed refreshing after notification : {}", e.to_detailed_string());
                }
            }
        } else {
            warn!("User is not logged");
        }
    } else {
        warn!("No matching user");
    }

    // We de not return an error to not panic MS APIs
    Ok(())
}

pub async fn renew_for(db: &DatabaseConnection, user: &User, ms_user: &MSUser) -> DataResult<()> {
    let mut subscriptions: Vec<MSSubscription> = db.single_query(
        r"
            FOR subscription IN subscriptions
                FILTER subscription.user == @id
                RETURN subscription
        ",
        json!({
            "id": &user.id
        })
    ).await?;

    if subscriptions.len() == 0 {
        let subscription = microsoft::subscribe(
            ms_user,
            "/me/messages?$filter=contains(subject, 'QCM')"
        ).await?;

        db.add("subscriptions", MSSubscription {
            id: subscription.id.clone(),
            user: user.id.clone(),
            expires_at: subscription.expires_at.clone()
        }).await?;

        info!(
            "Registered subscription '{}' expiring at '{}'",
            subscription.id,
            subscription.expires_at
        );

        return Ok(())
    }

    let mut subscription = subscriptions.swap_remove(0);
    if Utc::now() + Duration::hours(2) <= subscription.expires_at {
        return Ok(())
    }

    let expires_at = microsoft::renew_subscription(
        ms_user,
        &subscription.id
    ).await?;

    subscription.expires_at = expires_at;

    db.replace("subscriptions", &subscription.id, subscription.clone()).await?;

    info!(
        "Renewed subscription '{}', now expiring at '{}'",
        subscription.id,
        subscription.expires_at
    );

    Ok(())
}

pub async fn remove_for(db: &DatabaseConnection, user: &User) -> DataResult<()> {
    let subscriptions: Vec<MSSubscription> = db.single_query(
        r"
            FOR subscription IN subscriptions
                FILTER subscription.user == @id
                RETURN subscription
        ",
        json!({
            "id": &user.id
        })
    ).await?;

    let session = user.session.as_ref().ok_or(DataError::NotLogged)?;

    for subscription in subscriptions {
        microsoft::unsubscribe(&session.ms_user, &subscription.id).await?;
        db.remove("subscriptions", &subscription.id).await?;

        info!("Removing subscription '{}'", subscription.id);
    }

    Ok(())
}