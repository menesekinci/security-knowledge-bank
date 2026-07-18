---
source: "languages/rust/actix-axum-security.md"
title: "🦀 Actix-Web & Axum Security Guide"
heading: "7. Security Headers"
category: "language-vuln"
language: "rust"
severity: "high"
tags: [authentication, configuration, cors, extractor, language-vuln, limiting, middleware, ordering, rate, rust]
chunk: 8/10
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