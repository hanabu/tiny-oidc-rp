// SPDX-License-Identifier: MIT
use crate::error::AuthenticationFailedError;
use crate::{Error, IdToken, Provider};

#[derive(Clone, Debug)]
pub enum OidcResponseMode {
    /// For server side Web app.
    FormPost,
    /// For single page Web app.
    Fragment,
}

// &oidc_response_mode as &str
impl std::ops::Deref for OidcResponseMode {
    type Target = str;
    fn deref(&self) -> &str {
        match self {
            Self::FormPost => "form_post",
            Self::Fragment => "fragment",
        }
    }
}

/// OpenID Connect relying party client
#[derive(Clone, Debug)]
pub struct Client<P: Provider> {
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    response_mode: OidcResponseMode,
    provider: P,
}

impl<P: Provider> Client<P> {
    /// Create authn URL with query parameter
    pub fn auth_url(&self, session: &Session) -> url::Url {
        // append queries to authorize endpoint
        let mut authurl = self.provider.authorization_endpoint();
        authurl
            .query_pairs_mut()
            .append_pair("scope", "openid profile email")
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.client_id)
            .append_pair("nonce", &session.nonce())
            .append_pair("state", &session.state())
            .append_pair("response_mode", &self.response_mode)
            .append_pair("redirect_uri", &self.redirect_uri)
            .append_pair("code_challenge_method", "S256")
            .append_pair("code_challenge", &session.pkce_challenge());

        authurl
    }

    /// Authenticate user with `state`, `code`
    ///
    /// `state`, `code` are retrived from HTTP query parameters or form body.
    /// `session` is retrived from HTTP cookie.
    pub async fn authenticate(
        &self,
        state: &str,
        code: &str,
        session: &Session,
    ) -> Result<IdToken, Error> {
        // Check state mismatch (possible CSRF)
        if state != session.state() {
            return Err(Error::BadRequest);
        }

        // Prepare token endpoint request
        let code_verifier = session.pkce_verifier();
        let params = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("client_id", &self.client_id),
            ("client_secret", &self.client_secret),
            ("redirect_uri", &self.redirect_uri),
            ("code_verifier", &code_verifier),
        ];

        // Send POST request to token endpoint
        let response = reqwest::Client::new()
            .post(self.provider.token_endpoint().clone())
            .form(&params)
            .send()
            .await?;

        if let Err(err) = response.error_for_status_ref() {
            // Error, log body
            let err_body = response.text().await?;
            log::warn!("Token endpoint returns error {}", err_body);

            Err(err.into())
        } else {
            // Ok, decode body as JSON
            let token_response = response.json::<OidcTokenEndpointResponse>().await?;
            log::debug!("Token endpoint returns {:?}", token_response);

            // Decode ID Token string.
            //   Skip JWS signature validation here,
            //   because code flow can trust issuer by TLS server certificate validation
            let id_token = IdToken::decode_without_jws_validation(&token_response.id_token)?;

            self.validate_claims(&id_token, session)?;
            Ok(id_token)
        }
    }

    /// Validate ID token claims
    /// See also [OpenID connect spec 3.1.3.7. ID Token Validation](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation)
    fn validate_claims(
        &self,
        id_token: &IdToken,
        session: &Session,
    ) -> Result<(), AuthenticationFailedError> {
        use std::time::SystemTime;

        if !self.provider.validate_iss(&id_token.iss) {
            log::info!("Invalid iss {}", id_token.iss);
            return Err(AuthenticationFailedError::ClaimValidationError.into());
        }

        if id_token.aud != self.client_id {
            log::info!("Invalid aud {}", id_token.aud);
            return Err(AuthenticationFailedError::ClaimValidationError);
        }

        if &id_token.nonce != &session.nonce() {
            log::info!("Invalid nonce {}", id_token.nonce);
            return Err(AuthenticationFailedError::ClaimValidationError);
        }

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |t| t.as_secs());
        if id_token.iat > now + 60 || now > id_token.exp {
            // token expired
            log::info!(
                "Invalid iat {} or exp {} : now = {}",
                id_token.iat,
                id_token.exp,
                now
            );
            return Err(AuthenticationFailedError::ClaimValidationError);
        }

        Ok(())
    }
}

pub struct ClientBuilder<P: Provider> {
    client_id: Option<String>,
    client_secret: Option<String>,
    redirect_uri: Option<String>,
    response_mode: OidcResponseMode,
    provider: P,
}

impl<P: Provider> ClientBuilder<P> {
    /// Client builder from OpenID connect Provider
    pub(crate) fn from_provider(provider: P) -> Self {
        Self {
            client_id: None,
            client_secret: None,
            redirect_uri: None,
            response_mode: OidcResponseMode::FormPost,
            provider,
        }
    }

    /// Build OpenID connect Client
    pub fn build(self) -> Option<Client<P>> {
        match self {
            Self {
                client_id: Some(client_id),
                client_secret: Some(client_secret),
                redirect_uri: Some(redirect_uri),
                response_mode,
                provider,
            } => Some(Client {
                client_id,
                client_secret,
                redirect_uri,
                response_mode,
                provider,
            }),
            _ => {
                // Some elements are not initialized.
                None
            }
        }
    }

    /// Client ID
    pub fn client_id(self, client_id: &str) -> Self {
        let mut builder = self;
        builder.client_id = Some(client_id.to_string());
        builder
    }

    /// Client secret
    pub fn client_secret(self, client_secret: &str) -> Self {
        let mut builder = self;
        builder.client_secret = Some(client_secret.to_string());
        builder
    }

    /// Redirect URI
    pub fn redirect_uri(self, redirect_uri: &str) -> Self {
        let mut builder = self;
        builder.redirect_uri = Some(redirect_uri.to_string());
        builder
    }

    /// Response mode
    pub fn response_mode(self, response_mode: OidcResponseMode) -> Self {
        let mut builder = self;
        builder.response_mode = response_mode;
        builder
    }
}

/// OpenID connect login session
pub struct Session {
    // 0..36=key, 36..72=state, 72..108=nonce, 108..144=pkce_verifier
    rand_bytes: [u8; 144],
}

impl Session {
    /// Start new OpenID connect session
    pub fn new_session() -> Result<Session, crate::Error> {
        // Make random bytes
        let mut rand_bytes = [0u8; 144];
        getrandom::fill(&mut rand_bytes).map_err(|e| {
            log::error!("getrandom failed with {:?}", e);
            crate::Error::InternalError
        })?;
        Ok(Session { rand_bytes })
    }

    /// Serialize session and returns (key, value) pair.
    /// Implementer should store `key` in browser session cookie or local storage,
    /// and store `(key,value)` pair in server side database.
    /// Both `key` and `value` is URL safe string
    pub fn save_session(&self) -> (String, String) {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        return (self.key(), URL_SAFE_NO_PAD.encode(&self.rand_bytes[36..]));
    }

    /// Deserialize session saved by `save_session()`
    /// Implementer should get session key from cookie,
    /// and load session_value from server side database.
    pub fn load_session(
        session_key: &str,
        session_value: &str,
    ) -> Result<Self, base64::DecodeSliceError> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        let mut rand_bytes = [0u8; 144];

        // Decode key & value
        URL_SAFE_NO_PAD.decode_slice(session_key, &mut rand_bytes[..36])?;
        URL_SAFE_NO_PAD.decode_slice(session_value, &mut rand_bytes[36..])?;

        Ok(Self { rand_bytes })
    }

    /// Base64Url(key) -> 48 chars
    pub fn key(&self) -> String {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        URL_SAFE_NO_PAD.encode(&self.rand_bytes[..36])
    }

    /// Base64Url(state) -> 48 chars
    fn state(&self) -> String {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        URL_SAFE_NO_PAD.encode(&self.rand_bytes[36..72])
    }

    /// Base64Url(nonce) -> 48 chars
    fn nonce(&self) -> String {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        URL_SAFE_NO_PAD.encode(&self.rand_bytes[72..108])
    }

    /// PKCE code_challenge in Base64 string
    fn pkce_challenge(&self) -> String {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        use sha2::{Digest, Sha256};

        // PKCE code_challenge=Base64Url(SHA256(pkce_verifier))
        let challenge_byte = Sha256::digest(&self.pkce_verifier().as_bytes());

        URL_SAFE_NO_PAD.encode(&challenge_byte)
    }

    /// PKCE code_verifier in Base64 string
    fn pkce_verifier(&self) -> String {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        // code_verifier = Base64Url(pkce_verifier)
        URL_SAFE_NO_PAD.encode(&self.rand_bytes[108..144])
    }
}

/// Response body JSON from token endpoint
#[derive(Debug, serde::Deserialize)]
struct OidcTokenEndpointResponse {
    // access_token: Option<String>,
    id_token: String,
}
