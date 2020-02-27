use serde::{Serialize, Deserialize};

use super::{User, UserError};
use crate::db::DatabaseConnection;

pub async fn is_admin(db: &DatabaseConnection, user: &User) -> Result<bool, UserError> {
    let result: Vec<u32> = db.single_query(
        r"
            FOR obj IN admins
                FILTER obj.promo == @promo
                RETURN obj.admin
        ",
        json!({
            "promo": &user.cri_user.promo
        })
    ).await?;

    Ok(result.get(0).map(|id| id == user.id).unwrap_or(false))
}

pub async fn add_delegate(db: &DatabaseConnection, user: &User) -> Result<bool, UserError> {

}

async fn get_admin_infos(db: &DatabaseConnection, user: &User) -> Result<AdminInfo, UserError> {
    let result: Vec<AdminInfo> = db.single_query(
        r"
            FOR obj IN admins
                FILTER obj.promo == @promo
                RETURN obj
        ",
        json!({
            "promo": &user.cri_user.promo
        })
    ).await?;

    if result.len() == 0 {
        
    }
}

#[derive(Serialize, Deserialize)]
struct AdminInfo {
    promo: String,
    admin: u32,
    delegates: Vec<u32>
}