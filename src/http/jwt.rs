use std::{fmt, error, str};
use serde::de::DeserializeOwned;

pub fn decode<T: DeserializeOwned>(jwt: &str) -> Result<T, ParsingError> {
    let split: Vec<_> = jwt.split(".").collect();

    if let Some(str) = split.get(1) {
        if let Ok(bytes) = base64::decode(str) {
            if let Ok(content) = str::from_utf8(&bytes) {
                let result: Result<T, serde_json::Error> = serde_json::from_str(content);

                if let Ok(obj) = result {
                    return Ok(obj);
                }
            }
        }
    }

    Err(ParsingError {})
}

#[derive(Debug)]
pub struct ParsingError;

impl fmt::Display for ParsingError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "JWT format error")
    }
}

impl error::Error for ParsingError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}