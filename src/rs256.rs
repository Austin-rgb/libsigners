use crate::{
    common::Claims,
    signer_core::{Sign, Validate},
};
use anyhow::Result;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};

#[derive(Clone)]
pub struct RS256Signer {
    enc_key: EncodingKey,
    header: Header,
}

#[derive(Clone)]
pub struct RS256Validator {
    dec_key: DecodingKey,
    validation: Validation,
}

impl RS256Signer {
    pub fn default(aud: String, private_key:String) -> Self {
        RS256Signer::new(private_key, aud)
    }

    pub fn new(private_key: String, aud: String) -> Self {
        let enc_key =
            EncodingKey::from_rsa_pem(private_key.as_bytes()).expect("invalid private key");
        let mut vald = Validation::new(Algorithm::RS256);
        vald.set_audience(&[aud]);
        RS256Signer {
            enc_key,
            header: Header::new(Algorithm::RS256),
        }
    }
}

impl RS256Validator {
    pub fn default(aud: String, public_key:String) -> Self {
        RS256Validator::new(public_key, aud)
    }

    pub fn new(public_key: String, aud: String) -> Self {
        let dec_key = DecodingKey::from_rsa_pem(public_key.as_bytes()).expect("invalid public key");
        let mut vald = Validation::new(Algorithm::RS256);
        vald.set_audience(&[aud]);
        RS256Validator {
            dec_key,
            validation: vald,
        }
    }
}

impl Sign for RS256Signer {
    fn sign(&self, claims: &Claims) -> Result<String> {
        Ok(encode(&self.header, claims, &self.enc_key)?)
    }
}
impl Validate for RS256Validator {
    fn validate(&self, token: &str) -> Result<Claims> {
        let data = decode::<Claims>(token, &self.dec_key, &self.validation)?;
        Ok(data.claims)
    }
}
