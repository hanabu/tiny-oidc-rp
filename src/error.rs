/// tiny-oidc-rp Errors
#[derive(Debug)]
pub enum Error {
    /// Invalid request to RP - Implementer shoud return 400
    BadRequest,
    /// Authentication failed - Implementer shoud return 401
    AuthenticationFailed(AuthenticationFailedError),
    /// Internal error - Implementer shoud return 500
    InternalError,
    /// ID Provider token endpoint returns error - Implementer shoud return 502
    BadGateway(reqwest::Error),
}

impl From<AuthenticationFailedError> for Error {
    fn from(err: AuthenticationFailedError) -> Self {
        Self::AuthenticationFailed(err)
    }
}

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Self {
        Self::BadGateway(err)
    }
}
#[derive(Debug)]
pub enum AuthenticationFailedError {
    ClaimValidationError,
    JwsDecodeError,
    Base64DecodeError(base64::DecodeError),
    JsonDecodeError(serde_json::Error),
}

impl From<base64::DecodeError> for AuthenticationFailedError {
    fn from(err: base64::DecodeError) -> Self {
        Self::Base64DecodeError(err)
    }
}

impl From<serde_json::Error> for AuthenticationFailedError {
    fn from(err: serde_json::Error) -> Self {
        Self::JsonDecodeError(err)
    }
}
