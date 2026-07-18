# 🦀 Actix-Web & Axum Security Guide
> **Severity:** High


> **Category:** Languages / Rust / Web Framework Security
> **Last Updated:** July 2026
> **Description:** Deep dive into Actix-Web and Axum security — extractor security, middleware ordering, WebSocket authentication, and framework-specific vulnerabilities.

---

## 1. Extractor Security

Extractors are the primary way Rust web frameworks handle user input — they're also the #1 attack surface.

### Actix-Web: Path Extractor Injection

```rust
// VULNERABLE: Direct path extraction without validation
async fn get_user(user_id: Path<String>) -> impl Responder {
    let user_id = user_id.into_inner();
    
    // ⚠️ If user_id is "../../etc/passwd" — path traversal!
    // ⚠️ If user_id is "1 OR 1=1" — SQL injection risk!
    let user = db::find_user(&user_id).await;
    
    match user {
        Some(u) => HttpResponse::Ok().json(u),
        None => HttpResponse::NotFound().finish(),
    }
}

// SECURE: Validate extractor input
#[derive(Debug, Deserialize)]
struct UserId {
    #[serde(deserialize_with = "validate_uuid")]
    id: String,
}

fn validate_uuid<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    uuid::Uuid::parse_str(&s).map_err(|_| {
        serde::de::Error::custom("invalid UUID")
    })?;
    Ok(s)
}

async fn get_user(user_id: Path<UserId>) -> impl Responder {
    let user_id = user_id.into_inner();
    
    // Type-safe: user_id.id is a valid UUID
    let user = db::find_user(&user_id.id).await;
    
    match user {
        Some(u) => {
            // ⚠️ Still need authorization check!
            if authorized_to_view(&u) {
                HttpResponse::Ok().json(u)
            } else {
                HttpResponse::Forbidden().finish()
            }
        }
        None => HttpResponse::NotFound().finish(),
    }
}
```

### Axum: JSON Extractor with Validation

```rust
use axum::extract::Json;
use serde::Deserialize;
use validator::Validate;
use once_cell::sync::Lazy;
use regex::Regex;

// VULNERABLE: No input validation on JSON extractor
async fn create_user(Json(payload): Json<CreateUserRequest>) -> impl IntoResponse {
    // ⚠️ Directly uses user input — mass assignment!
    let user = User::create(payload.into()).await;
    (StatusCode::CREATED, Json(user))
}

// The validator crate's `regex` attribute takes a PATH to a compiled `Regex`
// static — NOT an inline pattern string. An inline `regex = "^...$"` does NOT
// compile. Define the Regex once, lazily:
static USERNAME_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[a-zA-Z0-9_]+$").unwrap());

// SECURE: Validate with validator crate
#[derive(Debug, Deserialize, Validate)]
struct CreateUserRequest {
    #[validate(length(min = 1, max = 100), regex(path = *USERNAME_RE))]
    username: String,
    
    #[validate(email)]
    email: String,
    
    #[validate(length(min = 8, max = 128))]
    password: String,
    
    // ⚠️ Don't let the user set their role
    #[serde(skip_deserializing)]  // Ignored from JSON input
    role: String,
}

async fn create_user(
    Json(payload): Json<CreateUserRequest>,
) -> Result<impl IntoResponse, AppError> {
    payload.validate()?;  // Returns 422 if invalid
    
    let user = User::create(payload).await?;
    Ok((StatusCode::CREATED, Json(user)))
}
```

### Axum: Query Parameter Injection

```rust
// VULNERABLE: Direct query string usage
async fn search_users(
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let query = params.get("q").unwrap_or(&String::new());
    
    // ⚠️ SQL injection: q = "'; DROP TABLE users; --"
    // ⚠️ NoSQL injection if using MongoDB
    let results = db::search(query).await;
    
    Json(results)
}

// SECURE: Extract typed query parameters
#[derive(Debug, Deserialize, Validate)]
struct SearchParams {
    #[validate(length(min = 1, max = 200))]
    q: String,
    
    #[serde(default = "default_limit")]
    #[validate(range(min = 1, max = 100))]
    limit: usize,
    
    #[serde(default)]
    offset: usize,
}

fn default_limit() -> usize { 20 }

async fn search_users(
    Query(params): Query<SearchParams>,
) -> Result<impl IntoResponse, AppError> {
    params.validate()?;
    
    // Use parameterized queries internally
    let results = db::search_safe(&params.q, params.limit, params.offset).await?;
    
    Ok(Json(results))
}
```

---

## 2. Middleware Ordering

Middleware order in Rust web frameworks is **critical** — put auth middleware in the wrong position and it may be bypassed entirely.

### The Ordering Problem

```
╔═══════════════════════════════════════════════════════╗
║                    CORRECT ORDER                       ║
╠═══════════════════════════════════════════════════════╣
║ 1. Logging/Metrics (no auth needed)                   ║
║ 2. Rate Limiting (throttle before auth)               ║
║ 3. CORS (needs to run early for preflight)            ║
║ 4. Authentication (validate credentials)              ║
║ 5. Authorization (check permissions)                  ║
║ 6. Request Validation (validate input)                ║
║ 7. CSRF Protection (state-changing operations)        ║
║ 8. Route Handler                                      ║
╚═══════════════════════════════════════════════════════╝
```

### Actix-Web: Middleware Order Example

```rust
// VULNERABLE: Auth middleware applied on individual routes (easy to miss)
use actix_web::{web, App, HttpServer, middleware::from_fn};

async fn start() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .wrap(Logger::default())
            .service(
                web::scope("/api")
                    // ⚠️ Auth NOT applied globally — easy to forget on new routes!
                    .route("/public", web::get().to(public_handler))
                    .route("/admin", web::get().to(admin_handler))  // Forgot auth!
                    .route("/users", web::get().to(users_handler))
            )
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}

// SECURE: Auth middleware on the entire scope
use actix_web::middleware::from_fn;
use actix_web::dev::{ServiceRequest, ServiceResponse, Transform, Service};
use std::future::{ready, Ready};

struct Authentication;
impl<S, B> Transform<S, ServiceRequest> for Authentication
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Future = Ready<...>>,
{
    // ... implementation
}

async fn start_secure() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .wrap(Logger::default())
            .wrap(Authentication)  // Auth applied to ALL routes
            .service(
                web::scope("/api")
                    .route("/public", web::get().to(public_handler))
                    .route("/admin", web::get().to(admin_handler))
                    .route("/users", web::get().to(users_handler))
            )
            .route("/health", web::get().to(health))  // Also protected!
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
```

### Axum: Middleware Order with Tower

```rust
use axum::{
    Router,
    middleware,
    routing::get,
};
use tower::ServiceBuilder;
use tower_http::{
    cors::CorsLayer,
    limit::RequestBodyLimitLayer,
    trace::TraceLayer,
};

// VULNERABLE: Wrong ordering
async fn vulnerable_app() -> Router {
    Router::new()
        .route("/api/users", get(get_users).post(create_user))
        .layer(CorsLayer::permissive())  // CORS AFTER auth — preflight fails!
        .layer(middleware::from_fn(auth_middleware))
        .layer(TraceLayer::new_for_http())
}

// SECURE: Correct middleware ordering
async fn secure_app() -> Router {
    let middleware_stack = ServiceBuilder::new()
        .layer(TraceLayer::new_for_http())     // 1. Logging
        .layer(RequestBodyLimitLayer::new(      // 2. Body limits before parsing
            10 * 1024 * 1024  // 10 MB
        ))
        .layer(CorsLayer::permissive())         // 3. CORS (before auth for preflight)
        .layer(middleware::from_fn(auth_layer))  // 4. Auth
        .layer(middleware::from_fn(rate_limit))  // 5. Rate limiting
        .into_inner();

    Router::new()
        .route("/api/public", get(public_handler))
        .route("/api/users", get(get_users).post(create_user))
        .layer(middleware_stack)
}
```

### Common Ordering Mistakes

```rust
// MISTAKE 1: CORS after auth — preflight requests fail auth
// Fix: CORS must be one of the outermost layers

// MISTAKE 2: Body limit after JSON extraction — already loaded in memory
// Fix: Body limits before any extraction

// MISTAKE 3: Auth middleware not in a shared layer stack
// Fix: One auth layer for all routes, with selective exclusion

// MISTAKE 4: CSRF before state initialization
// Fix: State init first, then security middleware
```

---

## 3. WebSocket Authentication

### Actix-Web: WebSocket Auth

```rust
use actix_web::{web, HttpRequest, HttpResponse};
use actix_ws;
use actix_web::Error;

// VULNERABLE: WebSocket without authentication
async fn ws_handler(req: HttpRequest, stream: web::Payload) -> Result<HttpResponse, Error> {
    // ⚠️ Any client can establish a WebSocket connection — no auth!
    let (response, _session, _msg_stream) = actix_ws::handle(&req, stream)?;
    Ok(response)
}

// SECURE: WebSocket with token validation
async fn secure_ws_handler(
    req: HttpRequest,
    stream: web::Payload,
    jwt_service: web::Data<JwtService>,
) -> Result<HttpResponse, Error> {
    // 1. Extract token from query string or header
    let token = req
        .query_string()
        .split('&')
        .find_map(|param| {
            let mut parts = param.splitn(2, '=');
            match (parts.next(), parts.next()) {
                (Some("token"), Some(value)) => Some(value.to_string()),
                _ => None,
            }
        })
        .or_else(|| {
            req.headers()
                .get("Authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
                .map(|s| s.to_string())
        });
    
    // 2. Validate token
    match token {
        Some(t) if jwt_service.validate(t).is_ok() => {
            // Extract user info
            let claims = jwt_service.validate(t).unwrap();
            req.extensions_mut().insert(AuthenticatedUser {
                id: claims.sub,
                role: claims.role,
            });
            
            // 3. Accept connection with authenticated user context
            let (response, session, msg_stream) = actix_ws::handle(&req, stream)?;
            // Store user context from req.extensions
            Ok(response)
        }
        _ => {
            // 4. Reject unauthorized connection
            Ok(HttpResponse::Unauthorized().finish())
        }
    }
}
```

### Axum: WebSocket Auth

```rust
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State, Query,
    },
    response::IntoResponse,
};
use serde::Deserialize;

// VULNERABLE: WebSocket without auth
async fn ws_handler(ws: WebSocketUpgrade) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket))
}

async fn handle_socket(mut socket: WebSocket) {
    // ⚠️ No authentication — any connection accepted
    while let Some(msg) = socket.recv().await {
        // Process message
        if let Ok(Message::Text(text)) = msg {
            // ⚠️ Handle potentially malicious input
        }
    }
}

// SECURE: WebSocket with auth
#[derive(Debug, Deserialize)]
struct WsQuery {
    token: String,
}

async fn secure_ws_handler(
    ws: WebSocketUpgrade,
    Query(query): Query<WsQuery>,
    State(auth): State<AuthService>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    // 1. Validate token before upgrading
    let user = auth.validate_token(&query.token)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid token".into()))?;
    
    // 2. Only upgrade if authenticated
    Ok(ws.on_upgrade(move |socket| handle_authenticated_socket(socket, user)))
}

async fn handle_authenticated_socket(
    mut socket: WebSocket,
    user: AuthenticatedUser,
) {
    // User is authenticated — proceed with authorization checks per action
    while let Some(msg) = socket.recv().await {
        if let Ok(Message::Text(text)) = msg {
            // Parse action and validate authorization
            match serde_json::from_str::<WsAction>(&text) {
                Ok(action) if user.can_perform(&action) => {
                    // Process authorized action
                }
                _ => {
                    let _ = socket.send(Message::Text(
                        r#"{"error": "unauthorized"}"#.into()
                    )).await;
                }
            }
        }
    }
}
```

---

## 4. CORS Configuration

```rust
// NOTE: `Origin` was renamed to `AllowOrigin` in modern tower-http.
use tower_http::cors::{CorsLayer, Any, AllowOrigin};

// VULNERABLE: Permissive CORS
let cors = CorsLayer::new()
    .allow_origin(Any)              // ⚠️ Any origin allowed
    .allow_methods(Any)             // ⚠️ Any method allowed
    .allow_headers(Any);            // ⚠️ Any header allowed

// SECURE: Restrictive CORS
let cors = CorsLayer::new()
    .allow_origin([
        "https://app.example.com".parse::<HeaderValue>().unwrap(),
        "https://admin.example.com".parse::<HeaderValue>().unwrap(),
    ])
    .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
    .allow_headers([AUTHORIZATION, CONTENT_TYPE, ACCEPT])
    .max_age(Duration::from_secs(3600));  // Cache preflight
```

---

## 5. Rate Limiting

```rust
// This example is Axum (note the Json/State extractors), so the responses
// must be Axum types too — return `(StatusCode, ...)` / `impl IntoResponse`,
// NOT Actix's `HttpResponse` (mixing the two frameworks does not compile).
use axum::{extract::State, Json, http::StatusCode, response::IntoResponse};

// VULNERABLE: No rate limiting — brute force, DoS
async fn login(Json(creds): Json<Credentials>) -> impl IntoResponse {
    // Can be called unlimited times
    if verify_credentials(&creds).await {
        (StatusCode::OK, Json(generate_token())).into_response()
    } else {
        StatusCode::UNAUTHORIZED.into_response()
    }
}

// SECURE: Rate limiting with governor
use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter};
use std::num::NonZeroU32;
use std::sync::Arc;

async fn secure_login(
    State(rate_limiter): State<Arc<DefaultKeyedRateLimiter<String>>>,
    Json(creds): Json<Credentials>,
) -> impl IntoResponse {
    // Rate limit per IP
    // (in real code, get client IP from ConnectInfo<SocketAddr>)
    if rate_limiter.check_key(&creds.ip).is_err() {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }

    if verify_credentials(&creds).await {
        (StatusCode::OK, Json(generate_token())).into_response()
    } else {
        StatusCode::UNAUTHORIZED.into_response()
    }
}
```

---

## 6. Actix-Web Specific: Unsafe Code Risks

Actix-Web historically used `unsafe` extensively (improved in newer versions). However:

```rust
// Risk: RefCell in middleware
// Actix's middleware system uses RefCell internally — misuse causes runtime panics
use std::cell::RefCell;

struct StatefulMiddleware {
    counter: RefCell<u32>,
}

impl<S, B> Transform<S, ServiceRequest> for StatefulMiddleware {
    type Transform = StatefulMiddlewareService<S>;
    
    fn new_transform(&self, service: S) -> Self::Transform {
        StatefulMiddlewareService {
            service,
            counter: RefCell::new(0),
        }
    }
}

// Panic risk: Two simultaneous requests will panic!
// Use Mutex instead for shared state
use std::sync::Mutex;

struct SafeMiddleware {
    counter: Mutex<u32>,
}
```

---

## 7. Security Headers

```rust
use tower_http::set_header::SetResponseHeaderLayer;
use axum::response::Response;
use http::header;

async fn add_security_headers(response: Response) -> Response {
    // This can be done as middleware
}

// SECURE: Add via tower_http
let app = Router::new()
    .route("/", get(handler))
    .layer(SetResponseHeaderLayer::overriding(
        header::STRICT_TRANSPORT_SECURITY,
        "max-age=31536000; includeSubDomains; preload"
            .parse()
            .unwrap(),
    ))
    .layer(SetResponseHeaderLayer::overriding(
        header::CONTENT_SECURITY_POLICY,
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
            .parse()
            .unwrap(),
    ))
    .layer(SetResponseHeaderLayer::overriding(
        header::X_FRAME_OPTIONS,
        "DENY".parse().unwrap(),
    ))
    .layer(SetResponseHeaderLayer::overriding(
        header::X_CONTENT_TYPE_OPTIONS,
        "nosniff".parse().unwrap(),
    ));
```

---

## 8. Actix/Axum Security Checklist

- [ ] All path/query extractors validate input type, length, and format
- [ ] JSON extractors use validation crates (validator, garde)
- [ ] Middleware order: Logging → CORS → Auth → Rate Limit → Routes
- [ ] WebSocket connections validate tokens before upgrade
- [ ] WebSocket actions authorize each message, not just the connection
- [ ] CORS is restricted to specific origins
- [ ] Rate limiting applied to auth endpoints
- [ ] Security headers (HSTS, CSP, XFO, XCTO) added via middleware
- [ ] Request body size is limited
- [ ] `unsafe` blocks reviewed and documented
- [ ] Sensitive data not leaked in error responses
- [ ] Logging does not include tokens, passwords, or PII

---

## References

- [Actix-Web Security Documentation](https://actix.rs/docs/security/)
- [Axum Security Best Practices](https://docs.rs/axum/latest/axum/#security)
- [RustSec Advisory Database](https://rustsec.org/advisories/)
- [Tower-http CORS](https://docs.rs/tower-http/latest/tower_http/cors/)
- [OWASP REST Security Cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html)
- [Governor Rate Limiting Crate](https://docs.rs/governor/latest/governor/)
- [The Rust Secure Code Working Group](https://github.com/rust-secure-code)
