---
source: "languages/rust/actix-axum-security.md"
title: "🦀 Actix-Web & Axum Security Guide"
heading: "1. Extractor Security"
category: "language-vuln"
language: "rust"
severity: "high"
tags: [authentication, configuration, cors, extractor, language-vuln, limiting, middleware, ordering, rate, rust]
chunk: 2/10
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