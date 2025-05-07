// SPDX-License-Identifier: MIT
//
// Sign in with Google example
//

use axum::extract::{Query, State};
use axum::http::{StatusCode, header::HeaderMap};
use axum::response::Html;
type GoogleClient = tiny_oidc_rp::Client<tiny_oidc_rp::GoogleProvider>;

// for Debug run on localhost, remove __Host- prefix
//   since Chrome, Edge reject it on http://localhost
#[cfg(debug_assertions)]
const SESSION_COOKIE_NAME: &str = "debug-session";
// for Production, __Host- prefix
#[cfg(not(debug_assertions))]
const SESSION_COOKIE_NAME: &str = "__Host-session";
const SESSION_PAYLOAD_OIDC: u8 = 0;
const SESSION_PAYLOAD_USER: u8 = 1;

struct AppState {
    oidc_client: GoogleClient,
    session_store: InMemoryLoginSessionStore,
    cookie_key: tiny_oidc_rp::session_store::SessionStoreKey,
}

#[tokio::main]
async fn main() -> Result<(), lambda_http::Error> {
    use axum::{Router, routing::get};
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

    // Cookie key
    let cookie_key = tiny_oidc_rp::session_store::SessionStoreKey::new(
        0,
        &std::env::var("COOKIE_SECRET").unwrap(),
    )
    .unwrap();

    let app_state = std::sync::Arc::new(AppState {
        oidc_client,
        session_store: InMemoryLoginSessionStore::new(),
        cookie_key,
    });

    // build routes
    let app = Router::new()
        .route("/login", get(oidc_start_auth))
        .route("/login/callback", get(oidc_return_from_idp))
        .route("/login/result", get(oidc_result))
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
    let auth_url = state.oidc_client.auth_url(&session, None);

    // store session state
    state.session_store.store(&session).await;

    // Redirect to authorization endpoint
    let mut headers = HeaderMap::new();
    headers.insert(
        header::LOCATION,
        header::HeaderValue::from_str(&auth_url.to_string()).unwrap(),
    );
    // Login session key in Cookie
    let cookie = state
        .cookie_key
        .encrypt(SESSION_COOKIE_NAME, &session.key(), SESSION_PAYLOAD_OIDC)
        .unwrap()
        .same_site(cookie::SameSite::Lax)
        .build();
    headers.insert(
        header::SET_COOKIE,
        header::HeaderValue::from_str(&cookie.to_string()).unwrap(),
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
    session_cookie: SessionCookie,
    State(state): State<std::sync::Arc<AppState>>,
    Query(auth_result): Query<OidcAuthResult>,
) -> axum::response::Result<(StatusCode, HeaderMap, &'static str)> {
    use axum::http::StatusCode;
    use axum::http::header;
    use axum::response::ErrorResponse;

    // Login session key from cookie
    let session_key = if let SessionCookie::OidcSessionKey(session_key) = session_cookie {
        session_key
    } else {
        log::error!("No OIDC session key in cookie");
        return Err(ErrorResponse::from(StatusCode::BAD_REQUEST));
    };

    // Load login session state
    // Removing from session store is important to prevent replay attacks
    let session = state
        .session_store
        .get_remove(&session_key)
        .await
        .ok_or(ErrorResponse::from(StatusCode::BAD_REQUEST))?;

    // Get ID token from token endpoint
    let idtoken = state
        .oidc_client
        .authenticate::<GoogleIdTokenExtraClaims>(&auth_result.state, &auth_result.code, &session)
        .await
        .map_err(|e| {
            log::error!("Cookie decode error {:?}", e);
            ErrorResponse::from(StatusCode::BAD_REQUEST)
        })?;
    // If you don't need extra claims, call as authenticate::<()>(...)

    // Logged in session cookie
    let user = User {
        sub: idtoken.subject().to_string(),
        name: idtoken.name().unwrap_or_default().to_string(),
        email: idtoken.email().unwrap_or_default().to_string(),
        picture_url: idtoken
            .extra()
            .picture
            .as_deref()
            .unwrap_or_default()
            .to_string(),
    };
    let user_cookie = state
        .cookie_key
        .encrypt(SESSION_COOKIE_NAME, &user, SESSION_PAYLOAD_USER)
        .unwrap()
        .same_site(cookie::SameSite::Lax)
        .build();

    // Redirect to /login/result page with User session cookie
    let mut headers = HeaderMap::new();
    headers.insert(
        header::LOCATION,
        header::HeaderValue::from_static("/login/result"),
    );
    headers.insert(
        header::SET_COOKIE,
        header::HeaderValue::from_str(&user_cookie.to_string()).unwrap(),
    );

    Ok((StatusCode::SEE_OTHER, headers, ""))
}

/// Print OIDC login result
async fn oidc_result(session_cookie: SessionCookie) -> axum::response::Result<Html<String>> {
    use axum::http::StatusCode;
    use axum::response::ErrorResponse;

    // Extract user infomation from cookie
    let user = if let SessionCookie::UserSession(user) = session_cookie {
        user
    } else {
        log::error!("No user information in cookie");
        return Err(ErrorResponse::from(StatusCode::BAD_REQUEST));
    };

    // <img> for picture url
    let img = if user.picture_url.is_empty() {
        "".to_string()
    } else {
        // !!! CAUTION !!! You must escape string for production
        format!("<img src={} alt=\"[Your avatar]\" />", user.picture_url)
    };

    // Make body
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
        user.sub,
        user.name,
        user.email,
        img
    );

    Ok(Html(body))
}

/// Extra ID token claims
#[derive(serde::Deserialize)]
struct GoogleIdTokenExtraClaims {
    picture: Option<String>,
}

/// Session cookie
enum SessionCookie {
    OidcSessionKey(String),
    UserSession(User),
}

/// User information in Cookie
#[derive(serde::Deserialize, serde::Serialize)]
struct User {
    sub: String,
    name: String,
    email: String,
    picture_url: String,
}

impl axum::extract::FromRequestParts<std::sync::Arc<AppState>> for SessionCookie {
    type Rejection = axum::http::StatusCode;

    // Extract SessionCookie from axum Request
    async fn from_request_parts(
        parts: &mut http::request::Parts,
        state: &std::sync::Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        use axum::http::StatusCode;
        let cookies = axum_extra::extract::CookieJar::from_request_parts(parts, state)
            .await
            .map_err(|_e| StatusCode::BAD_REQUEST)?;
        if let Some(session_cookie) = cookies.get(SESSION_COOKIE_NAME) {
            match tiny_oidc_rp::session_store::SessionStoreKey::payload_ver(&session_cookie) {
                Some(SESSION_PAYLOAD_OIDC) => {
                    let session_key = state
                        .cookie_key
                        .decrypt::<String>(&session_cookie)
                        .map_err(|_| StatusCode::BAD_REQUEST)?;
                    Ok(Self::OidcSessionKey(session_key))
                }
                Some(SESSION_PAYLOAD_USER) => {
                    let user = state
                        .cookie_key
                        .decrypt::<User>(&session_cookie)
                        .map_err(|_| StatusCode::BAD_REQUEST)?;
                    Ok(Self::UserSession(user))
                }
                _ => Err(StatusCode::BAD_REQUEST),
            }
        } else {
            Err(StatusCode::BAD_REQUEST)
        }
    }
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
