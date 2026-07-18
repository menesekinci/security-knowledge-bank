---
source: "common/api-security/grpc-security.md"
title: "gRPC Security"
heading: "Overview"
category: "api-security"
language: "common"
severity: "medium"
tags: [api-security, message, mtls, overview, reflection, size, table]
chunk: 2/9
---

## Overview

gRPC is a high-performance RPC framework widely used in microservice architectures. Its binary protocol, HTTP/2 transport, and protobuf serialization introduce security considerations distinct from REST. This document covers TLS/mTLS, reflection API risks, message size limits, authentication interceptors, and related CVEs.

---