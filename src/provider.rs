//! OpenID connect ID Provider
use serde::Deserialize;
use std::borrow::Cow;
use std::collections::HashMap;

/// OpenID Connect ID provider issuer
trait Issuer {
    fn validate_iss(iss: &str) -> bool;
}

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
pub struct MicrosoftTenantProvider {}
impl MicrosoftTenantProvider {
    /// Any tenant issuer
    pub fn any_tenant() -> Provider {
        Provider {
            authorization_endpoint: MICROSOFT_ANY_PROVIDER.authorization_endpoint,
            issuer: MICROSOFT_ANY_PROVIDER.issuer,
            jwks_uri: MICROSOFT_ANY_PROVIDER.jwks_uri,
            token_endpoint: MICROSOFT_ANY_PROVIDER.token_endpoint,
        }
    }

    /// Specific tenant issure (Restrict specific Azure AD organization)
    pub fn tenant(tenant_uuid: &str) -> Provider {
        Provider {
            authorization_endpoint: MICROSOFT_ANY_PROVIDER.authorization_endpoint,
            issuer: Cow::Owned(format!(
                "https://login.microsoftonline.com/{}/v2.0",
                tenant_uuid
            )),
            jwks_uri: MICROSOFT_ANY_PROVIDER.jwks_uri,
            token_endpoint: MICROSOFT_ANY_PROVIDER.token_endpoint,
        }
    }
}

const MICROSOFT_ANY_PROVIDER: Provider = Provider {
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
