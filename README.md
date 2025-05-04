# tiny-oidc-rp: Tiny OpenID Connect Relying Party

[![crates.io](https://img.shields.io/crates/v/tiny-oidc-rp?label=latest)](https://crates.io/crates/tiny-oidc-rp)
[![API docs](https://docs.rs/tiny-oidc-rp/badge.svg)](https://docs.rs/tiny-oidc-rp)

`tiny-oidc-rp` is a Rust implementation of [OpenID Connect](https://openid.net/connect/) relying party.
This crate is intended for server-side implementation and it supports [code flow](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth) only.
I have no plan to support [implicit flow](https://openid.net/specs/openid-connect-core-1_0.html#ImplicitFlowAuth) nor WASM on web frontend.

## Expected use

You can make your site "Sign in with \<some social ID\>"

- To implement web site for small group authentication with Google ID.
- To implement intranet web service authentication with Microsoft Azure Entra ID.
- etc.

## Usage

See [examples](examples/) .
