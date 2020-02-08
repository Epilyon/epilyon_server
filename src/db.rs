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
use serde_json::{Value, json, Error};
use reqwest::{Method as HttpMethod, Client as HttpClient, Error as HttpError};

pub type DBResult<T> = Result<T, DatabaseError>;

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
        DatabaseError::Unauthorized => DatabaseError::InvalidCredentials {
            username: String::from(username)
        },
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

        for col in vec!["users", "next_qcms", "qcm_histories", "mimos", "options"] {
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
                DatabaseError::NotFound => Ok(false),
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

    #[allow(dead_code)]
    pub async fn get<T>(&self, collection: &str, key: &str) -> DBResult<T>
        where T: serde::de::DeserializeOwned
    {
        let mut result = self.request(
            HttpMethod::GET,
            &format!("document/{}/{}", collection, key),
            None
        ).await?;

        result["_id"] = Value::Null;
        result["_key"] = Value::Null;
        result["_rev"] = Value::Null;

        serde_json::from_value(result).map_err(DatabaseError::from)
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
    path: &str,
    content: Option<Value>,
    token: Option<&str>
) -> DBResult<Value> {
    use DatabaseError::*;

    let mut builder = http.request(method, path);

    if let Some(tok) = token {
        builder = builder.header("Authorization", format!("Bearer {}", tok));
    }

    if let Some(cont) = content {
        builder = builder.json(&cont);
    }

    let value: Value = builder.send().await
        .map_err(|error| HttpError { error })?
        .json::<Value>().await
        .map_err(|e| ParsingError { error: e.to_string() })?;

    if let Some(true) = value["error"].as_bool() {
        return Err(match value["code"].as_i64().unwrap_or_else(|| 500) {
            401 => Unauthorized,
            404 => NotFound,
            code => UnknownArangoError {
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
    #[fail(display = "Invalid credentials for user '{}'", username)]
    InvalidCredentials {
        username: String
    },

    #[fail(display="Unauthorized action was performed")]
    Unauthorized,

    #[fail(display="The required element was not found")]
    NotFound,

    #[fail(display = "Unknown ArangoDB error : {}", error)]
    UnknownArangoError {
        error: ArangoError
    },

    #[fail(display = "JSON parsing error, server is probably not ArangoDB : {}", error)]
    ParsingError {
        error: String
    },

    #[fail(display = "Invalid ArangoDB response. This is really bad, please contact the devs. \
    Missing value '{}' from response '{}'", missing, response)]
    InvalidResponse {
        missing: String,
        response: String
    },

    #[fail(display = "HTTP communication error : {}", error)]
    HttpError {
        error: HttpError
    }
}

impl std::fmt::Display for ArangoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", &self.code, &self.message)
    }
}

impl From<serde_json::Error> for DatabaseError {
    fn from(e: Error) -> Self {
        DatabaseError::ParsingError {
            error: e.to_string()
        }
    }
}

trait TryGetString {
    fn try_get_string(&self, name: &str) -> DBResult<String>;
}

impl TryGetString for Value {
    fn try_get_string(&self, name: &str) -> DBResult<String> {
        self[name].as_str().map_or(Err(DatabaseError::InvalidResponse {
            missing: String::from(name),
            response: self.to_string()
        }), |s| Ok(String::from(s)))
    }
}