mod common;
mod hs256;
mod rs256;
mod signer_core;

pub use common::Claims;
pub use hs256::HS256Signer;
pub use rs256::{RS256Signer, RS256Validator};
pub use signer_core::{Sign, Validate};

use ferrumec::di::{AsyncFromEnv, EnvError};

impl AsyncFromEnv for Arc<dyn Sign> {
    async fn from_env(ctx: &crate::di::EnvContext) -> Result<Self, crate::di::EnvError> {
        let signer_type = ctx.get("sign.type")?;
        match signer_type {
            "hs256" => {
                Ok(Arc::new(HS256Signer::new(ctx.get("sign.aud")?.to_owned())) as Arc<dy>
            }
            "rs256" => Ok(Arc::new(RS256Signer::new(
                ctx.get("sign.private_key")?.to_string(),
                ctx.get("sign.aud")?.to_string(),
            )) as Arc<dyn Sign>),
            _ => Err(EnvError::new(format!(
                "Unsupported sign.type value: {signer_type}"
            ))),
        }
    }
}
