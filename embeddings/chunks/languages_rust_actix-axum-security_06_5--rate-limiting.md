---
source: "languages/rust/actix-axum-security.md"
title: "🦀 Actix-Web & Axum Security Guide"
heading: "5. Rate Limiting"
category: "language-vuln"
language: "rust"
severity: "high"
tags: [authentication, configuration, cors, extractor, language-vuln, limiting, middleware, ordering, rate, rust]
chunk: 6/10
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