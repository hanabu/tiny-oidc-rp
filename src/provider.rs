// SPDX-License-Identifier: MIT

//! OpenID connect ID Provider
use serde::Deserialize;

/// OpenID Connect ID provider issuer
pub trait Provider: Send + Sync + Sized {
    fn authorization_endpoint(&self) -> url::Url;
    fn token_endpoint(&self) -> url::Url;
    fn validate_iss(&self, iss: &str) -> bool;

    fn client(self) -> crate::client::ClientBuilder<Self> {
        crate::client::ClientBuilder::from_provider(self)
    }
}

/// OpenID connect provider from discovery
#[derive(Clone, Deserialize)]
pub struct DiscoveredProvider {
    authorization_endpoint: String,
    issuer: String,
    token_endpoint: String,
}

impl DiscoveredProvider {
    /// Create Provider from OpenID connect discovery endpoint
    /// https://<provider>/.well-known/openid-configuration
    pub async fn from_discovery(
        discovery_url: &str,
        http_client: &reqwest::Client,
    ) -> Result<Self, reqwest::Error> {
        // Send HTTP request to OpenID connect discovery endpoint
        let resp = http_client.get(discovery_url).send().await?;

        // Parse body as OpenID connect discovery JSON format
        let provider: DiscoveredProvider = resp.json().await?;

        Ok(provider)
    }
}

impl Provider for DiscoveredProvider {
    fn authorization_endpoint(&self) -> url::Url {
        url::Url::parse(&self.authorization_endpoint).unwrap()
    }

    fn token_endpoint(&self) -> url::Url {
        url::Url::parse(&self.token_endpoint).unwrap()
    }

    fn validate_iss(&self, iss: &str) -> bool {
        &self.issuer == iss
    }
}

/// Google OpenID connect ID provider
/// https://accounts.google.com/.well-known/openid-configuration
#[derive(Clone)]
pub struct GoogleProvider {}
impl GoogleProvider {
    pub fn new() -> Self {
        Self {}
    }
}
impl Provider for GoogleProvider {
    fn authorization_endpoint(&self) -> url::Url {
        url::Url::parse("https://accounts.google.com/o/oauth2/v2/auth").unwrap()
    }

    fn token_endpoint(&self) -> url::Url {
        url::Url::parse("https://oauth2.googleapis.com/token").unwrap()
    }

    fn validate_iss(&self, iss: &str) -> bool {
        "https://accounts.google.com" == iss
    }
}

/// Microsoft OpenID connect ID provider
/// https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration
#[derive(Clone)]
pub struct MicrosoftTenantProvider {
    tenant_uuid: Option<String>,
}
impl MicrosoftTenantProvider {
    /// Any tenant issuer
    pub fn any_tenant() -> Self {
        Self { tenant_uuid: None }
    }

    /// Specific tenant issure (Restrict specific Azure AD organization)
    pub fn tenant(tenant_uuid: &str) -> Self {
        Self {
            tenant_uuid: Some(tenant_uuid.to_string()),
        }
    }
}

impl Provider for MicrosoftTenantProvider {
    fn authorization_endpoint(&self) -> url::Url {
        if let Some(tenant_uuid) = &self.tenant_uuid {
            url::Url::parse(&format!(
                "https://login.microsoftonline.com/{}/oauth2/v2.0/authorize",
                tenant_uuid
            ))
            .unwrap()
        } else {
            url::Url::parse("https://login.microsoftonline.com/common/oauth2/v2.0/authorize")
                .unwrap()
        }
    }

    fn token_endpoint(&self) -> url::Url {
        url::Url::parse("https://login.microsoftonline.com/common/oauth2/v2.0/token").unwrap()
    }

    fn validate_iss(&self, iss: &str) -> bool {
        if let Some(tenant_uuid) = &self.tenant_uuid {
            format!("https://login.microsoftonline.com/{}/v2.0", tenant_uuid) == iss
        } else {
            // any tenant
            iss.starts_with("https://login.microsoftonline.com/") && iss.ends_with("/v2.0")
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    /*
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
    */
}
