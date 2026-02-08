use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Claims {
    pub sub: String,
    pub user_id: String,
    pub iat: usize,
    pub jti: String, // new: unique token id (uuid)
    pub exp: usize,
}

impl Claims {
    pub fn new(username: String, user_id: String) -> Self {
        let iat = Utc::now();

        Claims {
            sub: username,
            user_id,
            iat: iat.timestamp() as usize,
            jti: Uuid::new_v4().to_string(),
            exp: (iat.timestamp() + 300) as usize,
        }
    }
}
