---
source: "languages/go/ssrf.md"
title: "SSRF — net/http, Custom Transports, and Server-Side Request Forgery"
category: "language-vuln"
language: "go"
chunk: 2
total_chunks: 8
heading: "Overview"
---

## Overview

Server-Side Request Forgery (SSRF) occurs when an attacker can make a server-side application make HTTP requests to an arbitrary destination. In Go, SSRF vulnerabilities are common because the standard `net/http` client makes it trivially easy to send requests to any URL — and AI-generated code rarely validates URLs before making HTTP calls.