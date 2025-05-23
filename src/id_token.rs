// SPDX-License-Identifier: MIT
use crate::error::AuthenticationFailedError;

/// OpenID connect ID Token.
///
/// More detail, see OpenID Connect Core specification
///
/// - [2. ID Token](https://openid.net/specs/openid-connect-core-1_0.html#IDToken) and
/// - [5.1 Standard Claims](https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims)
///
/// If you need additionan non-standard claims, make your own struct and specify it to authenticate().
/// ```ignore
/// #[derive(serde::Deserialize)]
/// struct IdTokenExtraClaims {
///     picture: Option<String>,
/// }
/// let id_token_with_picture = oidc_client
///     .authenticate::<IdTokenExtraClaims>(&state, &code, &session)?;
/// let picture_url = id_token_with_picture.extra().picture;
/// ```
#[derive(serde::Deserialize)]
pub struct IdToken<T = ()> {
    pub(crate) iss: String,   // Issuer
    pub(crate) sub: String,   // Subject (unique identifier)
    pub(crate) aud: String,   // Audience (must be same as client_id)
    pub(crate) exp: u64,      // Unix time expires at
    pub(crate) iat: u64,      // Unix time issued at
    pub(crate) nonce: String, // nonce (must be same as nonce of auth request)
    pub(crate) email: Option<String>,
    pub(crate) name: Option<String>,
    /// Extra claims by crate user
    #[serde(flatten)]
    pub(crate) extra: T,
}

impl<T> IdToken<T>
where
    T: serde::de::DeserializeOwned,
{
    /// Decode IdToken from JWS string
    /// Warning: This function does not validate JWS signature.
    /// You can use this function for "code flow" only.
    pub(crate) fn decode_without_jws_validation(
        jws: &str,
    ) -> Result<Self, AuthenticationFailedError> {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

        // Decode JWT
        let mut jws_elm = jws.split('.');
        let _jws_header = jws_elm.next();
        let jws_payload = jws_elm.next();
        let _jws_sign = jws_elm.next();

        if let Some(jws_payload) = jws_payload {
            let json_str = URL_SAFE_NO_PAD.decode(jws_payload)?;
            Ok(serde_json::from_slice(&json_str)?)
        } else {
            // Invalid JWS structure
            Err(AuthenticationFailedError::JwsDecodeError)
        }
    }
}

// expose ID Token values
impl<T> IdToken<T> {
    /// ID Token issuer
    pub fn issuer(&self) -> &str {
        &self.iss
    }

    /// Subject Identifier.
    ///  A locally unique and never reassigned identifier within the Issuer for the End-User.
    pub fn subject(&self) -> &str {
        &self.sub
    }

    /// End-User's preferred e-mail address.
    pub fn email(&self) -> Option<&str> {
        self.email.as_deref()
    }

    /// End-User's full name in displayable form including all name parts,
    /// possibly including titles and suffixes,
    /// ordered according to the End-User's locale and preferences.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Extra claims
    pub fn extra(&self) -> &T {
        &self.extra
    }
}
