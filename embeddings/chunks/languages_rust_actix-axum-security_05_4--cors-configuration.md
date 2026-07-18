---
source: "languages/rust/actix-axum-security.md"
title: "🦀 Actix-Web & Axum Security Guide"
heading: "4. CORS Configuration"
category: "language-vuln"
language: "rust"
severity: "high"
tags: [authentication, configuration, cors, extractor, language-vuln, limiting, middleware, ordering, rate, rust]
chunk: 5/10
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