---
source: "common/oauth2-security.md"
title: "OAuth 2.0 Security — Implicit Grant, Redirect URI, CSRF, PKCE, Token Leakage"
heading: "What Is OAuth 2.0?"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [checklist, common-vuln, cves, major, oauth, prevention, real-world, vibe, what]
chunk: 2/8
---

## What Is OAuth 2.0?

OAuth 2.0 is an authorization framework that enables third-party applications to obtain limited access to a user's resources on another service without exposing credentials. It is used by virtually every major platform — Google, Facebook, Microsoft, GitHub, Twitter — for both API authorization and delegated authentication (SSO).

**The problem:** OAuth 2.0 is extremely complex, and implementation errors are pervasive. The framework prioritizes flexibility over security, leaving many critical decisions to implementers — who get them wrong at alarming rates.

### Key OAuth Concepts

| Term | Description |
|------|-------------|
| **Resource Owner** | The user who owns the data |
| **Client** | The application requesting access |
| **Authorization Server** | Issues tokens after authentication |
| **Resource Server** | Hosts protected resources, validates tokens |
| **Access Token** | Credential used to access resources |
| **Refresh Token** | Used to obtain new access tokens |
| **Authorization Code** | Temporary code exchanged for tokens |
| **Scope** | Defines the level of access requested |
| **Redirect URI** | Where the user is sent after authorization |
| **State** | Opaque value to prevent CSRF attacks |

---