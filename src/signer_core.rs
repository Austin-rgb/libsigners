use anyhow::Result;

use crate::Claims;

pub trait Signer: Send + Sync + 'static {
    fn sign(&self, claims: &Claims) -> Result<String>;
    fn validate(&self, token: &str) -> Result<Claims>;
}
