---
source: "languages/rust/web-framework-risks.md"
title: "Web Framework Risks — Actix, Axum, Rocket Common Misconfigurations"
heading: "Framework-Specific Risks"
category: "language-vuln"
language: "rust"
severity: "high"
tags: [checklist, common, cross-framework, cves, framework-specific, language-vuln, overview, prevention, real, risks]
chunk: 4/6
---

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