// SPDX-License-Identifier: MIT
//
// Sign in with Google example

use axum::extract::{Extension, Form, TypedHeader};
use axum::http::{header::HeaderMap, StatusCode};
use axum::response::Html;
type GoogleClient = tiny_oidc_rp::Client<tiny_oidc_rp::GoogleProvider>;

#[tokio::main]
async fn main() -> Result<(), lambda_web::LambdaError> {
    use axum::{routing::get, routing::post, AddExtensionLayer, Router};
    use lambda_web::{is_running_on_lambda, run_hyper_on_lambda};
    use std::net::SocketAddr;
    use tiny_oidc_rp::{GoogleProvider, Provider};

    env_logger::init();

    // Google OpenID connect client
    let oidc_client = GoogleProvider::new()
        .client()
        .client_id(&std::env::var("OIDC_CLIENT_ID").unwrap())
        .client_secret(&std::env::var("OIDC_CLIENT_SECRET").unwrap())
        .redirect_uri(&std::env::var("OIDC_REDIRECT_URI").unwrap())
        .build()
        .unwrap();

    // build our application with a route
    let app = Router::new()
        .route("/login", get(oidc_start_auth))
        .route("/login", post(oidc_return_from_idp))
        .route("/", get(root))
        .layer(AddExtensionLayer::new(oidc_client))
        .layer(AddExtensionLayer::new(InMemoryLoginSessionStore::new()));

    if is_running_on_lambda() {
        // Run app on AWS Lambda
        run_hyper_on_lambda(app).await?;
    } else {
        // Run app on local server
        let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
        axum::Server::bind(&addr)
            .serve(app.into_make_service())
            .await?;
    }
    Ok(())
}

/// GET / : Shows login link
async fn root() -> Html<&'static str> {
    Html(
        r###"<!DOCTYPE html>
<html>
<head>
<title>Sign in with Google sample</title>
</head>
<body>
<h1>Sign in with Google sample</h1>
<p><a href="/login">Sign in with Google</a></p>
<p>
<a href="https://github.com/hanabu/tiny-oidc-rp">Source code</a>
</p>
</body>
</html>
"###,
    )
}

/// Redirect to IdP authorization endpoint
async fn oidc_start_auth(
    Extension(oidc_client): Extension<GoogleClient>,
    Extension(session_store): Extension<InMemoryLoginSessionStore>,
) -> (StatusCode, HeaderMap, &'static str) {
    use axum::http::header;

    // Generate OIDC state, nonce
    let session = tiny_oidc_rp::Session::new_session();
    // authorization endpoint URL with query parameters
    let auth_url = oidc_client.auth_url(&session);

    // store session
    let cookie_val = session_store.store(&session).await;

    // Redirect to authorization endpoint
    let mut headers = HeaderMap::new();
    headers.insert(
        header::LOCATION,
        header::HeaderValue::from_str(&auth_url.to_string()).unwrap(),
    );
    // Login session key in Cookie
    headers.insert(
        header::SET_COOKIE,
        header::HeaderValue::from_str(&format!(
            "__Host-LoginSesion={}; path=/; Secure; HttpOnly; SameSite=None;",
            cookie_val
        ))
        .unwrap(),
    );
    (StatusCode::SEE_OTHER, headers, "")
}

#[derive(serde::Deserialize)]
struct OidcAuthResult {
    state: String,
    code: String,
}
/// Redirect from IdP with sessin and code
async fn oidc_return_from_idp(
    Form(auth_result): Form<OidcAuthResult>,
    TypedHeader(cookie): TypedHeader<axum::headers::Cookie>,
    Extension(oidc_client): Extension<GoogleClient>,
    Extension(session_store): Extension<InMemoryLoginSessionStore>,
) -> (HeaderMap, Html<String>) {
    use axum::http::header;

    // Login session key from cookie
    let session_key = cookie.get("__Host-LoginSesion").unwrap();

    // Load login session
    let session = session_store.load(session_key).await.unwrap();

    // Get ID token from token endpoint
    let idtoken = oidc_client
        .authenticate(&auth_result.state, &auth_result.code, &session)
        .await
        .unwrap();

    // Clear login session cookie
    let mut headers = HeaderMap::new();
    headers.insert(
        header::SET_COOKIE,
        header::HeaderValue::from_static(
            "__Host-LoginSesion=; path=/; Secure; HttpOnly; SameSite=None; Max-Age=0;",
        ),
    );

    // Debug print body
    let body = format!(
        r###"<!DOCTYPE html>
<html>
<head>
<title>Login result</title>
</head>
<body>
<h1>Login result</h1>
<ul>
<li>subject: {}</li>
<li>name: {}</li>
<li>email: {}</li>
</ul>
<hr />
<p><a href="/">Back</a></p>
</body>
</html>
"###,
        idtoken.subject(),
        idtoken.name().unwrap_or("-"),
        idtoken.email().unwrap_or("-"),
    );

    (headers, Html(body))
}

#[derive(Clone)]
struct InMemoryLoginSessionStore {
    store: std::sync::Arc<tokio::sync::Mutex<std::collections::HashMap<String, String>>>,
}

impl InMemoryLoginSessionStore {
    fn new() -> Self {
        Self {
            store: std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        }
    }

    async fn store(&self, session: &tiny_oidc_rp::Session) -> String {
        let (key, val) = session.save_session();

        let mut map = self.store.lock().await;
        map.insert(key.clone(), val);

        println!("Save session key \"{}\"", key);
        key
    }

    async fn load(&self, key: &str) -> Option<tiny_oidc_rp::Session> {
        let mut map = self.store.lock().await;

        println!("Loading session key \"{}\"", key);
        if let Some(val) = map.remove(key) {
            println!("Session key found \"{}\"", key);
            tiny_oidc_rp::Session::load_session(key, &val).ok()
        } else {
            None
        }
    }
}
