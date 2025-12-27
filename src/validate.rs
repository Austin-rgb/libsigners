use tokio::net::UnixStream;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use serde_json::json;

use crate::common::{Claims,signer_socket};

pub async fn validate_jwt(token: &str) -> Result<Claims, anyhow::Error> {
    let path = signer_socket();

    let stream = UnixStream::connect(&path).await?;
    let (r, mut w) = stream.into_split();
    let mut reader = BufReader::new(r);

    let request = json!({
        "cmd": "validate",
        "token": token
    });

    w.write_all(format!("{}\n", request).as_bytes()).await?;

    let mut response = String::new();
    reader.read_line(&mut response).await?;

    let response = response.trim();

    if let Some(claims_json) = response.strip_prefix("VALID ") {
        let claims: Claims = serde_json::from_str(claims_json)?;
        Ok(claims)
    } else if let Some(err) = response.strip_prefix("ERROR ") {
        Err(anyhow::anyhow!("JWT validation failed: {}", err))
    } else {
        Err(anyhow::anyhow!("Invalid signer response: {}", response))
    }
}

