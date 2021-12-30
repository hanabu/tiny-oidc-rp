// SPDX-License-Identifier: MIT
mod client;
mod error;
mod id_token;
mod provider;

// exports
pub use client::{Client, Session};
pub use error::Error;
pub use id_token::IdToken;
pub use provider::Provider;
pub use provider::{DiscoveredProvider, GoogleProvider, MicrosoftTenantProvider};
