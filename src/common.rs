use serde::{Serialize, Deserialize};
use uuid::Uuid;
use std::env;
use chrono::{Duration,Utc};
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Claims {
    pub sub: String,
 pub user_id: String,
    pub token_type: String, // "access" or "refresh"
    pub exp: usize,
    pub iat: usize,
    pub jti: String, // new: unique token id (uuid)
}

impl Claims {

pub fn new(username: String, user_id: String) -> Self {
        let iat = Utc::now();
        let exp = iat + Duration::minutes(15); // Access token:>

        Claims {
            sub: username,
            user_id,
            token_type: "access".to_string(),
            iat: iat.timestamp() as usize,
            exp: exp.timestamp() as usize,
            jti: Uuid::new_v4().to_string()
        }
    }
}
pub fn signer_socket() -> String {
    let tmpdir = env::var("TMPDIR").unwrap();
format!("{}/jwt-signer.sock", tmpdir)
}
