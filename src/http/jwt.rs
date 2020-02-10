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
use failure::Fail;
use serde::de::DeserializeOwned;

pub fn decode<T: DeserializeOwned>(jwt: &str) -> Result<T, JwtParsingError> {
    let split: Vec<_> = jwt.split(".").collect();
    let claims = split.get(1).ok_or(JwtParsingError::InvalidFormat)?;
    let bytes = base64::decode(claims)?;
    let content = std::str::from_utf8(&bytes)?;

    Ok(serde_json::from_str::<T>(content)?)
}

#[derive(Debug, Fail)]
pub enum JwtParsingError {
    #[fail(display = "Given string is not in valid base64 format : {}", error)]
    Base64Error {
        error: base64::DecodeError
    },

    #[fail(display = "Given base64 string is not UTF-8 when decoded : {}", error)]
    UTF8Error {
        error: std::str::Utf8Error
    },

    #[fail(display = "Invalid JWT format, unable to split")]
    InvalidFormat,

    #[fail(display = "Invalid JWT claims : {}", error)]
    InvalidClaims {
        error: serde_json::Error
    }
}

from_error!(base64::DecodeError, JwtParsingError, JwtParsingError::Base64Error);
from_error!(std::str::Utf8Error, JwtParsingError, JwtParsingError::UTF8Error);
from_error!(serde_json::Error, JwtParsingError, JwtParsingError::InvalidClaims);
