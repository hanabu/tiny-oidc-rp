//! JWS for OpenID connect

use serde::Deserialize;
use std::collections::HashMap;
use std::convert::TryFrom;

// RustCrypto RSA
#[cfg(rustcrypto)]
pub(super) type RsaPublicKey = rsa::RsaPublicKey;
// OpenSSL
#[cfg(not(rustcrypto))]
pub(super) type RsaPublicKey = openssl::rsa::Rsa<openssl::pkey::Public>;

/// ProviderKeys from Jwks
impl TryFrom<Jwks> for HashMap<String, RsaPublicKey> {
    type Error = std::io::Error;
    fn try_from(jwks: Jwks) -> Result<Self, Self::Error> {
        let mut keys = Self::new();

        for jwk in jwks.keys {
            if let Jwk::Rsa(jwk_rsa) = jwk {
                if jwk_rsa.use_for != "sig" {
                    log::warn!(
                        "Ignore invalid use of RSA key ({}, {})",
                        jwk_rsa.kid,
                        jwk_rsa.use_for
                    );
                    continue;
                }
                // Decode RSA public key
                match RsaPublicKey::try_from(&jwk_rsa) {
                    Ok(rsa) => {
                        keys.insert(jwk_rsa.kid, rsa);
                    }
                    Err(err) => {
                        log::error!("Invalid RSA public key: {:?}", err);
                    }
                }
            } else {
                // Skip non-RSA keys
            }
        }

        Ok(keys)
    }
}

/// Json Web Key Set for ID Provider's public key
#[derive(Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

/// Json Web Key for ID Provider's public key
/// Only supports RSA key type
#[derive(Deserialize)]
#[serde(tag = "kty")]
enum Jwk {
    // kty=RSA
    #[serde(rename = "RSA")]
    Rsa(JwkRsa),
    // kty=*
    #[serde(other)]
    Other,
}

#[derive(Deserialize)]
struct JwkRsa {
    #[serde(rename = "use")]
    use_for: String,
    kid: String,
    #[serde(deserialize_with = "deserialize_base64_url")]
    n: Vec<u8>,
    #[serde(deserialize_with = "deserialize_base64_url")]
    e: Vec<u8>,
}

// RustCrypto RSA from Jwk
#[cfg(rustcrypto)]
impl TryFrom<&JwkRsa> for RsaPublicKey {
    type Error = rsa::errors::Error;
    fn try_from(jwk: &JwkRsa) -> Result<Self, Self::Error> {
        use openssl::bn::BigNum;

        let n = rsa::BigUint::from_bytes_be(&jwk.n);
        let e = rsa::BigUint::from_bytes_be(&jwk.e);
        Self::new(n, e)
    }
}

// OpenSSL RSA from Jwk
#[cfg(not(rustcrypto))]
impl TryFrom<&JwkRsa> for RsaPublicKey {
    type Error = openssl::error::ErrorStack;
    fn try_from(jwk: &JwkRsa) -> Result<Self, Self::Error> {
        use openssl::bn::BigNum;

        let n = BigNum::from_slice(&jwk.n)?;
        let e = BigNum::from_slice(&jwk.e)?;
        Self::from_public_components(n, e)
    }
}

/// Deserialized BASE64URL encoded binary
fn deserialize_base64_url<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let b64urlstr: &str = serde::Deserialize::deserialize(deserializer)?;
    base64::decode_config(b64urlstr, base64::URL_SAFE_NO_PAD).map_err(serde::de::Error::custom)
}

#[cfg(test)]
mod test {
    use super::*;

    const MS_JWKS_STR: &str = include_str!("ms-jwks.json");
    const GOOGLE_JWKS_STR: &str = include_str!("google-jwks.json");

    // Parse Microsoft OIDC provider keys
    #[test]
    fn parse_google_jwks() {
        let jwks: Jwks = serde_json::from_str(GOOGLE_JWKS_STR).unwrap();

        for key in &jwks.keys {
            if let Jwk::Rsa(rsa_key) = key {
                let _pubkey = RsaPublicKey::try_from(rsa_key).unwrap();
            } else {
                panic!("Invalid key type")
            }
        }

        // Decode as RsaPublicKey
        let keys = HashMap::<String, RsaPublicKey>::try_from(jwks).unwrap();
        // Check if all keys are correctly decoded
        assert_eq!(keys.len(), 2);
    }

    // Parse Microsoft OIDC provider keys
    #[test]
    fn parse_microsoft_jwks() {
        let jwks: Jwks = serde_json::from_str(MS_JWKS_STR).unwrap();

        for key in &jwks.keys {
            if let Jwk::Rsa(rsa_key) = key {
                let _pubkey = RsaPublicKey::try_from(rsa_key).unwrap();
            } else {
                panic!("Invalid key type")
            }
        }

        // Decode as RsaPublicKey
        let keys = HashMap::<String, RsaPublicKey>::try_from(jwks).unwrap();
        // Check if all keys are correctly decoded
        assert_eq!(keys.len(), 7);
    }
}
