//! OpenID connect ID Provider

mod jwk;
use std::collections::HashMap;


struct ProviderKeys {
    // Time stamp of last fetch
    last_fetch: std::time::SystemTime,
    // map of (kid, rsa public key)
    keys: HashMap<String, jwk::RsaPublicKey>,
}
