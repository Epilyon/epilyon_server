use rocket_contrib::json::JsonValue;

use crate::sync::{AsyncState, EpiLock};
use crate::users::{StateManager, LoggedUser};

#[post("/state/get")]
pub fn get(user: LoggedUser, states: AsyncState<StateManager>) -> JsonValue {
    let states = states.epilock();

    json!({
        "state": states.get_for_user(user.user.uid)
    })
}
