// SPDX-License-Identifier: MIT
//
// Sign in with Google example
//

use axum::extract::{Query, State};
use axum::http::{header::HeaderMap, StatusCode};
use axum::response::Html;
use axum_extra::TypedHeader;
type GoogleClient = tiny_oidc_rp::Client<tiny_oidc_rp::GoogleProvider>;

struct AppState {
    oidc_client: GoogleClient,
    session_store: InMemoryLoginSessionStore,
}

#[tokio::main]
async fn main() -> Result<(), lambda_http::Error> {
    use axum::{routing::get, Router};
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

    let app_state = std::sync::Arc::new(AppState {
        oidc_client,
        session_store: InMemoryLoginSessionStore::new(),
    });

    // build routes
    let app = Router::new()
        .route("/login", get(oidc_start_auth))
        .route("/login/callback", get(oidc_return_from_idp))
        .route("/", get(root))
        .with_state(app_state);

    if std::env::var("AWS_LAMBDA_RUNTIME_API").is_ok() {
        // Run app on AWS Lambda
        lambda_http::run(app).await?;
    } else {
        // Run app on local server or Google Cloud Run, etc.
        let addr = std::env::var("LISTEN").unwrap_or("127.0.0.1:3000".to_string());

        println!("Server starts listening on {}", addr);
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        axum::serve(listener, app).await?;
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
    State(state): State<std::sync::Arc<AppState>>,
) -> axum::response::Result<(StatusCode, HeaderMap, &'static str)> {
    use axum::http::header;

    // Generate OIDC state, nonce
    let session = tiny_oidc_rp::Session::new_session().unwrap();
    // authorization endpoint URL with query parameters
    let auth_url = state.oidc_client.auth_url(&session);

    // store session state
    state.session_store.store(&session).await;

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
            "__Host-LoginSesion={}; path=/; Secure; HttpOnly; SameSite=Lax;",
            session.key()
        ))
        .unwrap(),
    );
    Ok((StatusCode::SEE_OTHER, headers, ""))
}

#[derive(serde::Deserialize)]
struct OidcAuthResult {
    state: String,
    code: String,
}
/// Redirect from IdP with sessin and code
async fn oidc_return_from_idp(
    TypedHeader(cookie): TypedHeader<axum_extra::headers::Cookie>,
    State(state): State<std::sync::Arc<AppState>>,
    Query(auth_result): Query<OidcAuthResult>,
) -> axum::response::Result<(HeaderMap, Html<String>)> {
    use axum::http::header;

    // Login session key from cookie
    let session_key = cookie.get("__Host-LoginSesion").unwrap();

    // Load login session state
    // Removing from session store is important to prevent replay attacks
    let session = state.session_store.get_remove(session_key).await.unwrap();

    // Get ID token from token endpoint
    let idtoken = state
        .oidc_client
        .authenticate::<GoogleIdTokenExtraClaims>(&auth_result.state, &auth_result.code, &session)
        .await
        .unwrap();
    // If you don't need extra claims, call as authenticate::<()>(...)

    let mut headers = HeaderMap::new();
    // Clear OIDC session cookie
    headers.insert(
        header::SET_COOKIE,
        header::HeaderValue::from_static(
            "__Host-LoginSesion=; path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0;",
        ),
    );
    // Session cookie
    headers.insert(
        header::SET_COOKIE,
        header::HeaderValue::from_static(
            "__Host-sesion=loggedin; path=/; Secure; HttpOnly; SameSite=Lax;",
        ),
    );

    // <img> for picture url
    let img = idtoken
        .extra()
        .picture
        .as_ref()
        .map(|pic_url| {
            // !!! CAUTION !!! You must escape string for production
            format!("<img src={} alt=\"[Your avatar]\" />", pic_url)
        })
        .unwrap_or_default();

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
<p>{}</p>
<hr />
<p><a href="/">Back</a></p>
</body>
</html>
"###,
        // !!! CAUTION !!! You must escape string for production
        idtoken.subject(),
        idtoken.name().unwrap_or("-"),
        idtoken.email().unwrap_or("-"),
        img
    );

    Ok((headers, Html(body)))
}

/// Extra ID token claims
#[derive(serde::Deserialize)]
struct GoogleIdTokenExtraClaims {
    picture: Option<String>,
}

/// This is example only, HashMap based in-memory session state store
/// For production use, you should implement persistent session store on some database.
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

    /// Save session state in HashMap
    async fn store(&self, session: &tiny_oidc_rp::Session) {
        let (key, val) = session.save_session();

        let mut map = self.store.lock().await;
        map.insert(key.clone(), val);
    }

    /// Load session state
    async fn get_remove(&self, key: &str) -> Option<tiny_oidc_rp::Session> {
        let mut map = self.store.lock().await;

        if let Some(val) = map.remove(key) {
            tiny_oidc_rp::Session::load_session(key, &val).ok()
        } else {
            None
        }
    }
}
