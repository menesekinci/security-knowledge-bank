---
source: "languages/rust/actix-axum-security.md"
title: "🦀 Actix-Web & Axum Security Guide"
heading: "3. WebSocket Authentication"
category: "language-vuln"
language: "rust"
severity: "high"
tags: [authentication, configuration, cors, extractor, language-vuln, limiting, middleware, ordering, rate, rust]
chunk: 4/10
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