---
source: "common/mass-assignment.md"
title: "Mass Assignment / Auto Binding"
heading: "Why Vibe Coding Makes This Worse"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [code, common, common-vuln, fixed, mass, vibe, vulnerable, what]
chunk: 3/9
---

## Why Vibe Coding Makes This Worse

- **AI loves ORMs and auto-mapping:** Frameworks like Rails, Laravel, Spring MVC, and Django REST Framework automatically map request data to objects
- **AI doesn't specify allowed fields:** Generated code uses `User.update(request.body)` without filtering
- **AI uses `**kwargs` / spread operators:** Python's `**data` or JavaScript's `...req.body` spread all fields
- **AI-generated GraphQL mutations:** Binds all fields from mutation arguments