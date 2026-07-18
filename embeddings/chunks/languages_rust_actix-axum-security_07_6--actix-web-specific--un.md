---
source: "languages/rust/actix-axum-security.md"
title: "🦀 Actix-Web & Axum Security Guide"
heading: "6. Actix-Web Specific: Unsafe Code Risks"
category: "language-vuln"
language: "rust"
severity: "high"
tags: [authentication, configuration, cors, extractor, language-vuln, limiting, middleware, ordering, rate, rust]
chunk: 7/10
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