use crate::common::Claims;
use crate::signer_core::Signer;
use anyhow::Result;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use std::env;

pub struct RS256Signer {
    enc_key: EncodingKey,
    dec_key: DecodingKey,
    header: Header,
    validation: Validation,
}

impl RS256Signer {
    pub fn default(aud: String) -> Self {
        let private_key = env::var("RSA_PRIVATE_KEY").expect("could not get RSA_PRIVATE_KEY value");
        let public_key = env::var("RSA_PUBLIC_KEY").expect("could not get RSA_PUBLIC_KEY");
        RS256Signer::new(private_key, public_key, aud)
    }

    pub fn new(private_key: String, public_key: String, aud: String) -> Self {
        let enc_key =
            EncodingKey::from_rsa_pem(private_key.as_bytes()).expect("invalid private key");
        let dec_key = DecodingKey::from_rsa_pem(public_key.as_bytes()).expect("invalid public key");
        let mut vald = Validation::new(Algorithm::RS256);
        vald.set_audience(&[aud]);
        RS256Signer {
            enc_key,
            dec_key,
            header: Header::new(Algorithm::RS256),
            validation: vald,
        }
    }
}

impl Signer for RS256Signer {
    fn sign(&self, claims: &Claims) -> Result<String> {
        Ok(encode(&self.header, claims, &self.enc_key)?)
    }

    fn validate(&self, token: &str) -> Result<Claims> {
        let data = decode::<Claims>(token, &self.dec_key, &self.validation)?;
        Ok(data.claims)
    }
}
