---
source: "common/api-security/graphql-security.md"
title: "GraphQL Security"
heading: "Overview"
category: "api-security"
language: "common"
severity: "medium"
tags: [api-security, attacks, batching, depth, introspection, leaks, overview, query, table]
chunk: 2/10
---

## Overview

GraphQL APIs present unique security challenges compared to REST. The single-endpoint nature, introspection capabilities, and flexible query structure introduce distinct attack vectors. This document covers introspection leaks, query depth limits, batching attacks, N+1 problems, and authentication in resolvers, with CVE-backed examples.

---