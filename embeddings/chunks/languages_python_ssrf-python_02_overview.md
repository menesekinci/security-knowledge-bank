---
source: "languages/python/ssrf-python.md"
title: "Python-Specific SSRF Patterns"
heading: "Overview"
category: "language-vuln"
language: "python"
severity: "high"
tags: [aiohttp, cve-2024-35195, cve-2024-37891, cve-2025-53643, language-vuln, overview, python, requests, ssrf, urllib3]
chunk: 2/8
---

## Overview

Server-Side Request Forgery (SSRF) in Python manifests uniquely due to the standard library's URL parsing behavior, redirect handling, and the ecosystem's HTTP libraries (`requests`, `httpx`, `aiohttp`). Python's `urllib` has historically been permissive about URL schemes and redirect following, creating SSRF vectors that differ from other languages.

---