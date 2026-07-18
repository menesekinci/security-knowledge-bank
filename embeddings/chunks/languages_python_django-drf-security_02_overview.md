---
source: "languages/python/django-drf-security.md"
title: "Django REST Framework Security Deep Dive"
heading: "Overview"
category: "language-vuln"
language: "python"
severity: "medium"
tags: [browsable, classes, language-vuln, overview, permission, python, serializer, throttling, validation]
chunk: 2/12
---

## Overview

Django REST Framework (DRF) is widely used for building APIs with Django. Its default settings are intentionally permissive, requiring developers to explicitly configure security. Common AI-produced misconfigurations include leaving `AllowAny` as the default permission class and exposing the Browsable API in production.

---