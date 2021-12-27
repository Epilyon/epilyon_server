use serde::{Deserialize, Serialize};

use crate::db::DatabaseConnection;
use crate::data::{DataResult, DataError};
use crate::user::User;
use crate::user::epitaf::{Task, fetch_tasks};

#[derive(Clone, Serialize, Deserialize)]
struct PromoTask {
    #[serde(rename = "_key")]
	promo: String,
	tasks: Vec<Task>
}

pub async fn get_tasks(db: &DatabaseConnection, user: &User) -> DataResult<Vec<Task>> {
    let all = get_promos_tasks(db, user).await?;
    Ok(all.tasks)
}

pub async fn refresh_tasks_db(db: &DatabaseConnection) -> DataResult<()> {
	let tasks = fetch_tasks().await;
	match tasks {
		Ok(t) => {
			let mut sorted_tasks: Vec<PromoTask> = Vec::new();
			for task in t {
				if task.visibility.ne("promotion".into()) {
					continue;
				}
				let check_promo = sorted_tasks
					.iter()
					.position(|t| t.promo == task.promotion.to_string());
				if let Some(p) = check_promo {
					sorted_tasks[p].tasks.push(task);
				} else {
					sorted_tasks.push(
						PromoTask {
							promo: task.promotion.to_string(),
							tasks: Vec::new()
						}
					);
					if let Some (pt) = sorted_tasks.last_mut() {
						pt.tasks.push(task);
					}
				}
			}
			for st in sorted_tasks {
				db.add_or_replace("tasks", st).await?;
			}
			return Ok(())
		},
		Err(error) => {
			return Err(DataError::EpitafError { error });
		}
	}
}

async fn get_promos_tasks(db: &DatabaseConnection, user: &User) -> DataResult<PromoTask> {
    match db.get::<PromoTask>("tasks", &user.cri_user.promo).await? {
        Some(m) => Ok(m),
        None => {
            let promo_task = PromoTask {
                promo: user.cri_user.promo.clone(),
                tasks: Vec::new()
            };

            db.add("tasks", &promo_task).await?;

            Ok(promo_task)
        }
    }
}