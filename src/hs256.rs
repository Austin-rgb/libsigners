use crate::common::Claims;
use crate::signer_core::Signer;
use anyhow::Result;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};

#[derive(Clone)]
pub struct HS256Signer {
    secret: String,
    header: Header,
    validation: Validation,
}

impl HS256Signer {
    pub fn new(secret: String) -> Self {
        let mut vald = Validation::new(Algorithm::HS256);
        vald.validate_aud = false;
        HS256Signer {
            secret,
            header: Header::new(Algorithm::HS256),
            validation: vald,
        }
    }
}

impl Signer for HS256Signer {
    type Claims = Claims;

    fn sign(&self, claims: &Claims) -> Result<String> {
        Ok(encode(
            &self.header,
            claims,
            &EncodingKey::from_secret(self.secret.as_bytes()),
        )?)
    }

    fn validate(&self, token: &str) -> Result<Claims> {
        let data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.secret.as_bytes()),
            &self.validation,
        )?;
        Ok(data.claims)
    }
}
