use crate::error::AuthenticationFailedError;
use crate::{Error, IdToken};

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
pub struct Client {
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    response_mode: OidcResponseMode,
    auth_url: url::Url,
    token_url: url::Url,
}

impl Client {
    /// Create authn URL with query parameter
    pub fn auth_url(&self, session: &Session) -> url::Url {
        // append queries to authorize endpoint
        let mut authurl = self.auth_url.clone();
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
            .post(self.token_url.clone())
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
            let id_token = IdToken::danger_decode_without_validation(&token_response.id_token)?;

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

        /*
        let matcher = wildmatch::WildMatch::new(&self.issuer);
        if !matcher.is_match(&id_token.iss) {
            log::info!("Invalid iss {}", id_token.iss);
            return Err(AuthenticationFailedReson::ClaimValidationError.into());
        }
        */

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

/// OpenID connect login session
pub struct Session {
    // 0..36=key, 36..72=state, 72..108=nonce, 108..144=pkce_verifier
    rand_bytes: [u8; 144],
}

impl Session {
    /// Start new OpenID connect session
    pub fn new_session() -> Session {
        use rand_core::{OsRng, RngCore};

        // Make random bytes
        let mut rand_bytes = [0u8; 144];
        OsRng.fill_bytes(&mut rand_bytes);
        Session { rand_bytes }
    }

    /// Serialize session and returns (key, value) pair.
    /// Implementer should store `key` in browser session cookie or local storage,
    /// and store `(key,value)` pair in server side database.
    /// Both `key` and `value` is URL safe string
    pub fn save_session(&self) -> (String, String) {
        return (
            base64::encode_config(&self.rand_bytes[..36], base64::URL_SAFE_NO_PAD),
            base64::encode_config(&self.rand_bytes[36..], base64::URL_SAFE_NO_PAD),
        );
    }

    /// Deserialize session saved by `save_session()`
    /// Implementer should get session key from cookie,
    /// and load session_value from server side database.
    pub fn load_session(
        session_key: &str,
        session_value: &str,
    ) -> Result<Self, base64::DecodeError> {
        if session_key.len() == 48 && session_value.len() == 144 {
            use base64::URL_SAFE_NO_PAD;
            let mut rand_bytes = [0u8; 144];

            // Decode key & value
            base64::decode_config_slice(&session_key, URL_SAFE_NO_PAD, &mut rand_bytes[..36])?;
            base64::decode_config_slice(&session_value, URL_SAFE_NO_PAD, &mut rand_bytes[36..])?;

            Ok(Self { rand_bytes })
        } else {
            Err(base64::DecodeError::InvalidLength)
        }
    }

    /// Base64Url(state) -> 48 chars
    fn state(&self) -> String {
        base64::encode_config(&self.rand_bytes[36..72], base64::URL_SAFE_NO_PAD)
    }

    /// Base64Url(nonce) -> 48 chars
    fn nonce(&self) -> String {
        base64::encode_config(&self.rand_bytes[72..108], base64::URL_SAFE_NO_PAD)
    }

    /// PKCE code_challenge in Base64 string
    fn pkce_challenge(&self) -> String {
        #[cfg(rustcrypto)]
        use sha2::{Digest, Sha256};

        // PKCE code_challenge=Base64Url(SHA256(pkce_verifier))
        // OpenSSL SHA256
        #[cfg(not(rustcrypto))]
        let challenge_byte = openssl::sha::sha256(&self.rand_bytes[108..144]);
        // Rust Crypto SHA256
        #[cfg(rustcrypto)]
        let challenge_byte = sha2::Sha256::digest(&self.rand_bytes[108..144]);

        base64::encode_config(&challenge_byte, base64::URL_SAFE_NO_PAD)
    }

    /// PKCE code_verifier in Base64 string
    fn pkce_verifier(&self) -> String {
        // code_verifier = Base64Url(pkce_verifier)
        base64::encode_config(&self.rand_bytes[108..144], base64::URL_SAFE_NO_PAD)
    }
}

/// Response body JSON from token endpoint
#[derive(Debug, serde::Deserialize)]
struct OidcTokenEndpointResponse {
    access_token: Option<String>,
    id_token: String,
}
