---
source: "languages/csharp/aspnet-auth-deep.md"
title: "ASP.NET Core Authentication Deep Dive"
category: "language-vuln"
language: "csharp"
chunk: 2
total_chunks: 12
heading: "Overview"
---

## Overview

ASP.NET Core offers multiple authentication schemes: Identity (cookie-based), JWT Bearer (API auth), and OpenID Connect (external providers). Misconfiguration of authentication logic is the #1 source of security vulnerabilities in ASP.NET Core applications.

---