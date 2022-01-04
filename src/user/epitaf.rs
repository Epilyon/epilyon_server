use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use failure::Fail;
use reqwest::{Client as HttpClient, Error as HttpError};

use crate::config::CONFIG;

#[derive(Clone, Serialize, Deserialize)]
pub struct Task {
    pub created_at: DateTime<Utc>,
	pub updated_at: DateTime<Utc>,
	pub short_id: String,
	pub visibility: String,
	pub promotion: u16,
	pub semester: Option<String>,
	pub class: Option<String>,
	pub region: Option<String>,
	pub title: String,
	pub subject: String,
	pub content: String,
	pub due_date: DateTime<Utc>,
	pub created_by_login: String,
	pub created_by: String,
	pub updated_by_login: Option<String>,
	pub updated_by: Option<String>,
}

#[derive(Deserialize)]
struct LoginResult {
    token: String
}

type EpitafResult<T> = Result<T, EpitafError>;

pub async fn fetch_tasks() -> EpitafResult<Vec<Task>> {
	let jwt = get_jwt().await?;

    let http = HttpClient::new();
	let url = format!("{}/tasks", CONFIG.epitaf_url);
    let res = http.get(&url)
        .header("Accept", "application/json")
        .bearer_auth(jwt)
        .send().await?
        .text().await?;

	let value: Vec<Task> = serde_json::from_str(&res)
		.map_err(move |e| EpitafError::RemoteError {
			method: "get".into(),
			url,
			request: String::new(),
			response: res,
			error: e
		})?;

	Ok(value)
}

async fn get_jwt() -> EpitafResult<String> {
    let http = HttpClient::new();
	let url = format!("{}/users/callback", CONFIG.epitaf_url);
	let res = http.post(&url)
		.bearer_auth(&CONFIG.epitaf_token)
		.send().await?
        .text().await?;

	let value: LoginResult = serde_json::from_str(&res)
		.map_err(move |e| EpitafError::RemoteError {
			method: "post".into(),
			url,
			request: String::new(),
			response: res,
			error: e
		})?;

    Ok(value.token)
}

#[derive(Fail, Debug)]
pub enum EpitafError {
    #[fail(display = "HTTP error during request")]
    HttpError {
        error: HttpError
    },

    #[fail(display = "Microsoft request was rejected")]
    RemoteError {
        method: String,
        url: String,
        request: String,
        response: String,
        error: serde_json::Error
    }
}

from_error!(reqwest::Error, EpitafError, EpitafError::HttpError);
