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
use std::fs;
use std::path::Path;
use std::process::exit;

use log::{info, warn, error};
use lazy_static::lazy_static;
use serde_derive::{Serialize, Deserialize};

lazy_static! {
    pub static ref CONFIG: EpiConfig = load();
}

#[derive(Serialize, Deserialize)]
pub struct EpiConfig {
    pub address: String,
    pub port: u16,

    pub db_host: String,
    pub db_port: u16,
    pub db_user: String,
    pub db_password: String,
    pub db_database: String,

    pub cri_url: String,
    pub cri_accessor_username: String,
    pub cri_accessor_password: String,
    pub cri_promos: Vec<String>,

    pub ms_tenant_url: String,
    pub ms_client_id: String,
    pub ms_scopes: Vec<String>,
    pub ms_redirect_uri: String,
    pub ms_webhook_uri: String,
    pub ms_secret: String,

    pub firebase_secret: String
}

fn default() -> EpiConfig {
    EpiConfig {
        address: "localhost".to_string(),
        port: 7899,

        db_host: "localhost".to_string(),
        db_port: 8529,
        db_user: "epilyon".to_string(),
        db_password: "".to_string(),
        db_database: "epilyon".to_string(),

        cri_url: "https://cri.epita.fr".to_string(),
        cri_accessor_username: "firstname.lastname".to_string(),
        cri_accessor_password: "password".to_string(),
        cri_promos: vec!["2024".to_string(), "2023".to_string()],

        ms_tenant_url: "https://login.microsoftonline.com/your_tenant_url".to_string(),
        ms_client_id: "your_client_id".to_string(),
        ms_scopes: vec!["openid".to_string(), "offline_access".to_string(), "profile".to_string(), "mail.read".to_string()],
        ms_redirect_uri: "http://localhost:7899/auth/redirect".to_string(),
        ms_webhook_uri: "http://localhost:7899/data/notify".to_string(),
        ms_secret: "your_secret_key".to_string(),

        firebase_secret: "your_very_secret_key".to_string()
    }
}

fn load() -> EpiConfig {
    let config_path = match std::env::var("EPILYON_CONFIG") {
        Ok(c) => c,
        Err(_) => "./epilyon.toml".to_string()
    };

    if !Path::new(&config_path).exists() {
        warn!("Configuration file at '{}' does not exist, creating a default one", config_path);

        let config = default();
        match toml::to_string(&config) {
            Ok(str) => match fs::write(&config_path, str) {
                Ok(_) => {
                    warn!("Fill it before restarting the server");
                    exit(0);
                },
                Err(e) => error!("Failed writing default config at '{}', please check if the parent folder exists \
                and if the program has the permission to write in there: {}", config_path, e)
            },
            Err(e) => error!("Failed serializing default config, this is very bad, please contact the devs: {}", e)
        }

        exit(1);
    }

    info!("Reading config from '{}'", config_path);

    match fs::read_to_string(config_path) {
        Ok(s) => match toml::from_str::<EpiConfig>(&s) {
            Ok(c) => c,
            Err(e) => {
                error!("Error while deserializing the config file, there is probably a syntax error in it: {}", e);
                exit(1);
            }
        },
        Err(e) => {
            error!("Error while reading the config file, the program may not have the permissions to read it: {}", e);
            exit(1);
        }
    }
}