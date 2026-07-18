---
source: "languages/rust/web-framework-risks.md"
title: "Web Framework Risks — Actix, Axum, Rocket Common Misconfigurations"
heading: "Common Cross-Framework Issues"
category: "language-vuln"
language: "rust"
severity: "high"
tags: [checklist, common, cross-framework, cves, framework-specific, language-vuln, overview, prevention, real, risks]
chunk: 3/6
---

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