---
source: "common/mass-assignment.md"
title: "Mass Assignment / Auto Binding"
heading: "What Is Mass Assignment?"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [code, common, common-vuln, fixed, mass, vibe, vulnerable, what]
chunk: 2/9
---

## What Is Mass Assignment?

Mass assignment (also called auto-binding or autobinding) occurs when a framework **automatically binds HTTP request parameters to object properties** without filtering which properties are allowed. An attacker adds extra parameters to a request to modify fields they shouldn't have access to.

**Simple example:** You send `{"name": "Alice", "role": "user"}` to update a profile. The attacker sends `{"name": "Alice", "role": "admin"}` and becomes an admin.