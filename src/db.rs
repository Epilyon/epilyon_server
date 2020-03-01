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
use failure::Fail;
use serde_json::{Value, json};
use reqwest::{Method as HttpMethod, Client as HttpClient, Error as HttpError};

pub type DBResult<T> = Result<T, DatabaseError>;

// TODO: Refresh ArangoDB JWT (1 month expiration)

#[derive(Clone)]
pub struct DatabaseConnection {
    http: HttpClient,
    host: String,
    port: u16,
    token: String,
    database: String
}

#[derive(Debug)]
pub struct ArangoError {
    code: i64,
    message: String
}

pub async fn open(
    host: &str,
    port: u16,
    username: &str,
    password: &str,
    database: &str
) -> DBResult<DatabaseConnection> {
    info!("Contacting ArangoDB at tcp://{}:{}...", host, port);

    let http = HttpClient::new();

    let auth = request(
        &http,
        HttpMethod::POST,
        &format!("http://{}:{}/_open/auth", host, port),
        Some(json!({
            "username": username,
            "password": password
        })),
        None
    ).await.map_err(|e| match e {
        DatabaseError::Unauthorized => DatabaseError::InvalidCredentials,
        _ => e
    })?;

    let conn = DatabaseConnection {
        http,
        host: String::from(host),
        port,
        token: String::from(auth.try_get_string("jwt")?),
        database: String::from(database)
    };

    if !conn.does_collection_exist("users").await? {
        info!("First launch, setting up database...");
    }

    for col in vec!["users", "next_qcms", "qcm_histories", "mimos", "options", "admins"] {
        if !conn.does_collection_exist(col).await? {
            info!("  - Creating table '{}'", col);
            conn.add_collection(col).await?;
        }
    }

    info!("Connected to the database");

    Ok(conn)
}

impl DatabaseConnection {
    pub async fn add_collection(&self, name: &str) -> DBResult<()> {
        self.request(
            HttpMethod::POST,
            "collection",
            Some(json!({
                "name": name
            }))
        ).await.map(|_| ())
    }

    pub async fn does_collection_exist(&self, name: &str) -> DBResult<bool> {
        let res = self.request(
            HttpMethod::GET,
            &format!("collection/{}", name),
            None
        ).await;

        match res {
            Ok(_) => Ok(true),
            Err(e) => match e {
                DatabaseError::NotFound { .. } => Ok(false),
                _ => Err(e)
            }
        }
    }

    pub async fn add<T>(&self, collection: &str, obj: T) -> DBResult<String>
        where T: serde::ser::Serialize
    {
        let res = self.request(
            HttpMethod::POST,
            &format!("document/{}", collection),
            Some(serde_json::to_value(obj)?)
        ).await?;

        Ok(res.try_get_string("_key")?)
    }

    pub async fn get<T>(&self, collection: &str, key: &str) -> DBResult<Option<T>>
        where T: serde::de::DeserializeOwned
    {
        let mut result = self.request(
            HttpMethod::GET,
            &format!("document/{}/{}", collection, key),
            None
        ).await?;

        result["_id"] = Value::Null;
        result["_rev"] = Value::Null;

        let result = serde_json::from_value(result)
            .map_err(DatabaseError::from);

        match result {
            Ok(doc) => Ok(Some(doc)),
            Err(e) => {
                if let DatabaseError::NotFound { .. } = e {
                    Ok(None)
                } else {
                    Err(e)
                }
            }
        }
    }

    pub async fn replace<T>(&self, collection: &str, key: &str, obj: T) -> DBResult<()>
        where T: serde::ser::Serialize
    {
        self.request(
            HttpMethod::PUT,
            &format!("document/{}/{}", collection, key),
            Some(serde_json::to_value(obj)?)
        ).await.map(|_| ())
    }

    pub async fn update<T>(&self, coll: &str, key: &str, obj: T) -> DBResult<()>
        where T: serde::ser::Serialize
    {
        self.request(
            HttpMethod::PATCH,
            &format!("document/{}/{}", coll, key),
            Some(serde_json::to_value(obj)?)
        ).await.map(|_| ())
    }

    pub async fn remove(&self, coll: &str, key: &str) -> DBResult<()> {
        self.request(
            HttpMethod::DELETE,
            &format!("document/{}/{}", coll, key),
            None
        ).await.map(|_| ())
    }

    pub async fn single_query<T>(&self, query: &str, params: Value) -> DBResult<T>
        where T: serde::de::DeserializeOwned
    {
        let res = self.request(
            HttpMethod::POST,
            "cursor",
            Some(json!({
                "query": query,
                "bindVars": params
            }))
        ).await?;

        Ok(serde_json::from_value(res["result"].clone())?)
    }

    async fn request(
        &self,
        method: HttpMethod,
        path: &str,
        content: Option<Value>
    ) -> DBResult<Value> {
         request(
             &self.http,
             method,
             &format!("http://{}:{}/_db/{}/_api/{}", self.host, self.port, self.database, path),
             content,
             Some(&self.token)
         ).await
    }
}

async fn request(
    http: &HttpClient,
    method: HttpMethod,
    url: &str,
    content: Option<Value>,
    token: Option<&str>
) -> DBResult<Value> {
    use DatabaseError::*;

    let mut builder = http.request(method.clone(), url);

    if let Some(tok) = token {
        builder = builder.header("Authorization", format!("Bearer {}", tok));
    }

    if let Some(cont) = content.as_ref() {
        builder = builder.json(cont);
    }

    let response = builder.send().await?.text().await?;
    let value: Value = serde_json::from_str(&response)
        .map_err(move |e| ParsingError {
            response,
            error: e
        })?;

    if let Some(true) = value["error"].as_bool() {
        let request = content
            .and_then(|v| serde_json::to_string_pretty(&v).ok())
            .unwrap_or(String::from(""));

        return Err(match value["code"].as_i64().unwrap_or_else(|| 500) {
            401 => Unauthorized,
            404 => NotFound {
                uri: method.to_string() + " " + url,
                request
            },
            code => RemoteError {
                uri: method.to_string() + " " + url,
                request,
                error: ArangoError {
                    code,
                    message: String::from(value.try_get_string("errorMessage")?)
                }
            }
        })
    }

    Ok(value)
}

#[derive(Debug, Fail)]
pub enum DatabaseError {
    #[fail(display = "Invalid credentials used for the database")]
    InvalidCredentials,

    #[fail(display="An unauthorized action was performed")]
    Unauthorized,

    #[fail(display="Can't find the requested element in the database")]
    NotFound {
        uri: String,
        request: String
    },

    #[fail(display = "Database request failed with an unknown error")]
    RemoteError {
        uri: String,
        request: String,
        error: ArangoError
    },

    #[fail(display = "JSON serialization error")]
    SerializingError {
        error: serde_json::Error
    },

    #[fail(display = "JSON parsing error, database is probably down")]
    ParsingError {
        response: String,
        error: serde_json::Error
    },

    #[fail(display = "Invalid database response")]
    InvalidResponse {
        missing: String,
        response: String
    },

    #[fail(display = "Database communication error")]
    HttpError {
        error: HttpError
    }
}

impl std::fmt::Display for ArangoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", &self.code, &self.message)
    }
}

trait TryGetString {
    fn try_get_string(&self, name: &str) -> DBResult<String>;
}

impl TryGetString for Value {
    fn try_get_string(&self, name: &str) -> DBResult<String> {
        self[name].as_str().map_or(Err(DatabaseError::InvalidResponse {
            missing: String::from(name),
            response: serde_json::to_string_pretty(self).unwrap_or(self.to_string())
        }), |s| Ok(String::from(s)))
    }
}

impl DatabaseError {
    pub fn to_detailed_string(&self) -> String {
        use DatabaseError::*;

        let mut result = String::new();
        result += &self.to_string();

        match self {
            NotFound { uri, request } => {
                result += &format!(
                    ", this usually happens when the requested database or collection doesn't exist.\n\
                    Request was on '{}' with body :\n{}",
                    uri,
                    request
                );
            },
            RemoteError { uri, request, error } => {
                result += &format!(", error is {} and request was on '{}' with body :\n{}", error, uri, request);
            },
            SerializingError { error } => {
                result += &format!(", serde dropped error : {}", error);
            },
            ParsingError { response, error } => {
                result += &format!(". Serde dropped error '{}' while parsing response :\n{}", error, response);
            },
            InvalidResponse { missing, response } => {
                result += &format!(" : missing field '{}' from response :\n{}", missing, response);
            },
            HttpError { error } => {
                result += &format!(", reqwest dropped error '{}'", error);
            },
            _ => {}
        }

        result
    }
}

from_error!(reqwest::Error, DatabaseError, DatabaseError::HttpError);
from_error!(serde_json::Error, DatabaseError, DatabaseError::SerializingError);
