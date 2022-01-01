# tiny-oidc-rp: Tiny OpenID Connect Relying Party

[![crates.io](https://img.shields.io/crates/v/tiny-oidc-rp?label=latest)](https://crates.io/crates/tiny-oidc-rp)

tiny-oidc-rp is Rust implementation of [OpenID Connect](https://openid.net/connect/) relying party.
This crate is intended for server-side implementation and it supports [code flow](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth) only.
I have no plan to support [implicit flow](https://openid.net/specs/openid-connect-core-1_0.html#ImplicitFlowAuth) nor WASM on web frontend.

### Expected use:

- To implement intranet web service authentication with Microsoft Azure ADFS.
- To implement web site for small group authentication with Google ID.
- etc.

## Usage

See [examples](examples/) .
