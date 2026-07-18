# Web Framework Risks — Actix, Axum, Rocket Common Misconfigurations
> **Severity:** High


## Overview

Rust web frameworks have matured significantly, powering production APIs at companies like Discord, Figma, and Cloudflare. However, AI-generated Rust web code frequently contains security misconfigurations that the compiler happily accepts. This document covers the three most popular frameworks — Actix Web, Axum, and Rocket — and their common pitfalls.

## Common Cross-Framework Issues

### 1. Missing Input Validation

Rust's type system does NOT automatically validate HTTP input. A common AI-generated mistake:

```rust
// AI-GENERATED — no input validation
#[derive(Deserialize)]
struct CreateUser {
    username: String,
    email: String,
    age: u8,  // Accepts 0-255, but business logic requires 18+
}

// Axum handler — no validation on decoded data
async fn create_user(Json(payload): Json<CreateUser>) -> impl IntoResponse {
    // Direct insert into database — no age check, no email format check
    sqlx::query("INSERT INTO users (username, email, age) VALUES ($1, $2, $3)")
        .bind(&payload.username)
        .bind(&payload.email)
        .bind(payload.age)
        .execute(&pool).await.unwrap();
    StatusCode::CREATED
}
```

**Risks**: 
- No age validation (13-year-old can register)
- No email format validation
- No length limits (DoS via 1MB username)
- SQL injection via `sqlx::query` if format strings are used

### 2. Leaking Internal Error Information

Frameworks have different default error behaviors:

```rust
// AI-GENERATED Axum — leaks internal error details
async fn get_user(Path(id): Path<u64>) -> Result<Json<User>, StatusCode> {
    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
        .bind(id)
        .fetch_one(&pool)
        .await
        .map_err(|e| {
            // LEAKS: tells attacker whether user exists vs. DB connection failure
            StatusCode::NOT_FOUND
        })?;
    Ok(Json(user))
}
```

**Better**: Return consistent, generic error responses.

## Framework-Specific Risks

### Actix Web

Actix Web historically had a reputation for overusing `unsafe`. While modern Actix has been largely rewritten to reduce unsafe, AI-generated Actix code may still use outdated patterns.

#### AI-Generated Vulnerability: App State without Sync Bounds

```rust
use actix_web::{web, App, HttpServer};

// AI-GENERATED — state not Sync, causing compile error or silent UB
struct AppState {
    counter: std::cell::Cell<u32>, // Cell is not Sync
}

async fn count(state: web::Data<AppState>) -> String {
    let c = state.counter.get(); // Compile error: cannot share Cell across threads
    state.counter.set(c + 1);
    format!("Count: {}", c)
}

// AI will often "fix" this incorrectly by adding unsafe impl Sync
unsafe impl Sync for AppState {} // DANGEROUS — data race!
```

**Secure Fix**: Use `Mutex`, `RwLock`, or `AtomicU32`.

```rust
struct AppState {
    counter: std::sync::atomic::AtomicU32,
}

async fn count(state: web::Data<AppState>) -> String {
    let c = state.counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    format!("Count: {}", c)
}
```

#### AI-Generated Vulnerability: Extractors Without Validation

```rust
// AI-GENERATED — direct path extraction, no access control
#[actix_web::get("/admin/users/{user_id}")]
async fn admin_get_user(user_id: web::Path<String>) -> HttpResponse {
    // No authentication check! Anyone can access this endpoint.
    let user_id = user_id.into_inner();
    // ...
}
```

### Axum

Axum (from the Tokio team) is currently the most popular Rust web framework. Its tower-based middleware makes it powerful, but AI code frequently misconfigures layers.

#### AI-Generated Vulnerability: CORS Misconfiguration

```rust
use axum::http::Method;
use tower_http::cors::{Any, CorsLayer};

// AI-GENERATED — permissive CORS (reflects origin)
let cors = CorsLayer::new()
    .allow_origin(Any)   // Accepts any origin!
    .allow_methods(Any)  // Any HTTP method
    .allow_headers(Any); // Any headers

// This allows any website to make authenticated requests to your API
```

**Secure Fix**:
```rust
let cors = CorsLayer::new()
    .allow_origin(cors::AllowOrigin::list([
        "https://myapp.com".parse().unwrap(),
    ]))
    .allow_methods([Method::GET, Method::POST])
    .max_age(Duration::from_secs(3600));
```

#### AI-Generated Vulnerability: No Rate Limiting

```rust
// AI-GENERATED — no DoS protection
let app = Router::new()
    .route("/api/expensive", post(expensive_handler))
    // No rate limiting! Attacker can call this 100K times/second
    .layer(TraceLayer::new_for_http());
```

**Secure Fix**: Add rate limiting middleware.
```rust
use tower_governor::{governor::GovernorConfigBuilder, GovernorLayer};

let gov_config = GovernorConfigBuilder::default()
    .per_second(10)    // 10 requests/second
    .burst_size(20)    // Allow burst up to 20
    .finish()
    .unwrap();

let app = Router::new()
    .route("/api/expensive", post(expensive_handler))
    .layer(GovernorLayer { config: Box::new(gov_config) });
```

### Rocket

Rocket uses compile-time request guards and derives for validation. AI-generated Rocket code tends to skip custom validation.

#### AI-Generated Vulnerability: Form Data Without Validation

```rust
use rocket::serde::Deserialize;
use rocket::{post, routes};

#[derive(Deserialize)]
struct LoginForm {
    pub username: String,
    pub password: String,
}

// AI-GENERATED — no CSRF protection, no rate limiting, no validation
#[post("/login", data = "<form>")]
fn login(form: Form<LoginForm>) -> Flash<Redirect> {
    // Direct authentication attempt
    if authenticate(&form.username, &form.password) {
        Flash::success(Redirect::to("/dashboard"), "Welcome!")
    } else {
        Flash::error(Redirect::to("/login"), "Invalid credentials")
    }
}
```

**Risks**:
- No CSRF token verification
- No password strength validation
- No rate limiting — brute force attack vector
- No timing-safe comparison (crypto vulnerability)

## Real CVEs

- **CVE-2023-44487 (HTTP/2 Rapid Reset)**: All Rust web frameworks using `hyper` or `h2` were affected. A client opens many HTTP/2 streams and immediately sends `RST_STREAM` for each, forcing costly server-side work at near-zero client cost. A protocol-level bug, not Rust-specific (CVSS 7.5), but it shows Rust web apps are not immune to high-severity CVEs.
- **CVE-2024-32650 / RUSTSEC-2024-0336 (rustls infinite-loop DoS)**: On a **blocking** rustls server, if a client sends `close_notify` right after `client_hello`, `ConnectionCommon::complete_io` never terminates — the thread spins at 100% CPU. A handful of such connections can starve a multithreaded (non-async) TLS server. CVSS 7.5. Affects rustls ≤ 0.23.4 (and 0.20–0.22 lines); fixed in 0.23.5 / 0.22.4 / 0.21.11. `rustls-tokio` async servers are not affected.
- **RUSTSEC-2023-0071 / CVE-2023-49092 (Marvin timing attack via `sqlx-mysql`)**: The `rsa` crate is not constant-time, so RSA operations leak private-key bits through a network-observable timing side channel (Marvin attack). It reaches web apps transitively — `sqlx-mysql`'s MySQL auth path pulls in `rsa`. CVSS 5.9, no fixed `rsa` release yet; mitigate by avoiding the affected auth path / monitoring the advisory. (This is a real `sqlx`-dependency-chain advisory — not the fabricated "Log4j SQL-injection" CVE-2022-23305, which is a Java issue.)

## Prevention Checklist

1. **Validate all inputs** — Use `validator` crate's `Validate` derive on structs for length, format, and range checks.
2. **Use type-safe extractors** — Never extract raw `String` from path/query; use `Path<u64>`, `Query<ValidatedParams>`.
3. **Configure CORS strictly** — Allow only specific origins, not `Any`.
4. **Add rate limiting** — `tower-governor` for Axum, `actix-governor` for Actix.
5. **Implement authentication middleware** — Never trust user-supplied session data without verification.
6. **Set security headers** — Use `tower-http`'s `SetResponseHeaderLayer` for HSTS, CSP, X-Frame-Options.
7. **Log securely** — Don't log tokens, passwords, or PII.
8. **Use `cargo audit`** — Vulnerabilities in `hyper`, `h2`, `tokio` affect all Rust web apps.
9. **Set body size limits** — Prevent DoS via large request bodies: `DefaultBodyLimit::max(256 * 1024)`.
10. **Generate CSRF tokens** — For Rocket, use `rocket_csrf`; for Axum/Actix, use `tower-sessions` with CSRF protection.
