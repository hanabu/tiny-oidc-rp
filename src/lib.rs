// SPDX-License-Identifier: MIT

//!
//! OpenID connect relaying party implementation
//! See [examples](https://github.com/hanabu/tiny-oidc-rp/tree/main/examples)
//!
mod client;
mod error;
mod id_token;
mod provider;

// exports
pub use client::{Client, ClientBuilder, Session};
pub use error::Error;
pub use id_token::IdToken;
pub use provider::Provider;
pub use provider::{DiscoveredProvider, GoogleProvider, MicrosoftTenantProvider};
