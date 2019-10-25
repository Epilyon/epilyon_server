use serde::Serialize;
use chrono::{DateTime, Utc};
use std::collections::HashMap;

pub struct StateManager {
    states: HashMap<usize, UserState>
}

impl StateManager {
    // TODO: Remove states of expired/invalidated sessions

    pub fn new() -> Self {
        StateManager {
            states: HashMap::new()
        }
    }

    pub fn get_for_user(&self, id: usize) -> Option<&UserState> {
        self.states.get(&id)
    }

    pub fn update(&mut self, id: usize, state: UserState) {
        self.states.insert(id, state);
    }
}

#[derive(Serialize)]
pub struct UserState {
    pub last_qcm: Option<QCMResult>
}

#[derive(Serialize)]
pub struct QCMResult {
    #[serde(skip_serializing)]
    last_mail: String, // MS id of the last QCM result mail, client don't need this
    date: DateTime<Utc>,
    values: HashMap<String, u8>
}