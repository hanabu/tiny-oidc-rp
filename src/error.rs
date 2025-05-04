// SPDX-License-Identifier: MIT

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

impl From<Error> for http::StatusCode {
    /// For convinience, convert crate::Error into HTTP status code
    fn from(e: Error) -> Self {
        use Error::*;
        match e {
            BadRequest => http::StatusCode::BAD_REQUEST,
            AuthenticationFailed(_) => http::StatusCode::UNAUTHORIZED,
            InternalError => http::StatusCode::INTERNAL_SERVER_ERROR,
            BadGateway(_) => http::StatusCode::BAD_GATEWAY,
        }
    }
}

/// Detail of authentication failure
#[derive(Debug)]
pub enum AuthenticationFailedError {
    /// Invalid claim in ID token. e.g., `iss`, `aud` mismatch, `exp` expires, etc.
    ClaimValidationError,
    JwsDecodeError,
}

impl From<base64::DecodeError> for AuthenticationFailedError {
    /// Base64 decode error in ID token JWS parser
    fn from(err: base64::DecodeError) -> Self {
        log::warn!("Invalid ID token: {:?}", err);
        Self::JwsDecodeError
    }
}

impl From<serde_json::Error> for AuthenticationFailedError {
    /// JSON decode error in ID token JWS parser
    fn from(err: serde_json::Error) -> Self {
        log::warn!("Invalid ID token: {:?}", err);
        Self::JwsDecodeError
    }
}
