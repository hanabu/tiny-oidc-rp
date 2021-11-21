//! OpenID connect ID Provider

mod jwk;
use serde::Deserialize;
use std::borrow::Cow;
use std::collections::HashMap;

/// OpenID connect provider
#[derive(Deserialize)]
pub struct Provider {
    authorization_endpoint: Cow<'static, str>,
    issuer: Cow<'static, str>,
    jwks_uri: Cow<'static, str>,
    token_endpoint: Cow<'static, str>,
    //    keys: ProviderKeys,
}

impl Provider {
    /// Create Provider from OpenID connect discovery endpoint
    /// https://<provider>/.well-known/openid-configuration
    pub async fn from_discovery(
        discovery_url: &str,
        http_client: &reqwest::Client,
    ) -> Result<Self, reqwest::Error> {
        // Send HTTP request to OpenID connect discovery endpoint
        let resp = http_client.get(discovery_url).send().await?;

        // Parse body as OpenID connect discovery JSON format
        let provider: Provider = resp.json().await?;

        Ok(provider)
    }
}

struct ProviderKeys {
    // Time stamp of last fetch
    last_fetch: std::time::SystemTime,
    // map of (kid, rsa public key)
    keys: HashMap<String, jwk::RsaPublicKey>,
}

/// Google OpenID connect ID provider
/// https://accounts.google.com/.well-known/openid-configuration
pub const GOOGLE_PROVIDER: Provider = Provider {
    authorization_endpoint: Cow::Borrowed("https://accounts.google.com/o/oauth2/v2/auth"),
    issuer: Cow::Borrowed("https://accounts.google.com"),
    jwks_uri: Cow::Borrowed("https://www.googleapis.com/oauth2/v3/certs"),
    token_endpoint: Cow::Borrowed("https://oauth2.googleapis.com/token"),
};

/// Microsoft OpenID connect ID provider
/// https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration
pub const MICROSOFT_PROVIDER: Provider = Provider {
    authorization_endpoint: Cow::Borrowed(
        "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    ),
    issuer: Cow::Borrowed("https://login.microsoftonline.com/*/v2.0"),
    jwks_uri: Cow::Borrowed("https://login.microsoftonline.com/common/discovery/v2.0/keys"),
    token_endpoint: Cow::Borrowed("https://login.microsoftonline.com/common/oauth2/v2.0/token"),
};

#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test]
    async fn discover_google() {
        let client = reqwest::Client::new();

        let provider = Provider::from_discovery(
            "https://accounts.google.com/.well-known/openid-configuration",
            &client,
        )
        .await
        .unwrap();

        assert_eq!(
            provider.authorization_endpoint,
            GOOGLE_PROVIDER.authorization_endpoint
        );
        assert_eq!(provider.issuer, GOOGLE_PROVIDER.issuer);
        assert_eq!(provider.jwks_uri, GOOGLE_PROVIDER.jwks_uri);
        assert_eq!(provider.token_endpoint, GOOGLE_PROVIDER.token_endpoint);
    }
}
