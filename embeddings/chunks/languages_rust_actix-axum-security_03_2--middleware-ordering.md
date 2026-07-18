---
source: "languages/rust/actix-axum-security.md"
title: "🦀 Actix-Web & Axum Security Guide"
heading: "2. Middleware Ordering"
category: "language-vuln"
language: "rust"
severity: "high"
tags: [authentication, configuration, cors, extractor, language-vuln, limiting, middleware, ordering, rate, rust]
chunk: 3/10
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