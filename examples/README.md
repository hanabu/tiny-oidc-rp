# Sign in with Google example

## Redirect URI

To run OpenID connect relaying party, you have to host redirect URI on HTTPS server where IdP redirect web browser with authentication code, and you need to register your redirect URI to IdP.

In this example, redirect URI is on the path `/login/callback`.  So, redirect URI should be `https://<yourserver>/login/callback`

## Prepare Google IdP

On [Google Cloud Platform - APIs & Services](https://console.cloud.google.com/apis/dashboard),

1. Create new project
2. Setup [OAuth consent screen](https://console.cloud.google.com/apis/credentials/consent)
3. Create OAuth 2.0 Client IDs in [Credentials](https://console.cloud.google.com/apis/credentials) page. You need to register redirect URI here.

Then, you get OpenID connect "Client ID" and "Client secret".

## Build

```console
$ cargo build --examples --release --features session-store
...
$ ls target/release/examples/sign-in-with-google
```

to build this example.

Or if you deploy to AWS Lambda, see [Build and deploy Rust binary to Lambda](https://github.com/hanabu/lambda-web/blob/main/Deploy.md) article.

## Deploy and run

To run this example, three environment variables are required.

- OIDC_CLIENT_ID : client ID obtained by Google IdP
- OIDC_CLIENT_SECRET : client secret obtained by Google IdP
- OIDC_REDIRECT_URI : `https://<your-server>/login/callback`
- COOKIE_SECRET : 40 or more random charactors for session Cookie encryption
