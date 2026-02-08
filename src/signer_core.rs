use anyhow::Result;
use serde::{Serialize, de::DeserializeOwned};

pub trait Signer: Send + Sync + 'static {
    type Claims: Serialize + DeserializeOwned + Send + Sync;

    fn sign(&self, claims: &Self::Claims) -> Result<String>;
    fn validate(&self, token: &str) -> Result<Self::Claims>;
}
