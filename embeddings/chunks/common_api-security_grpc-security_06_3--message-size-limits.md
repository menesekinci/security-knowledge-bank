---
source: "common/api-security/grpc-security.md"
title: "gRPC Security"
heading: "3. Message Size Limits"
category: "api-security"
language: "common"
severity: "medium"
tags: [api-security, message, mtls, overview, reflection, size, table]
chunk: 6/9
---

## 3. Message Size Limits

Without message size limits, malicious clients can:
- **Memory exhaustion** — send multi-gigabyte protobuf messages
- **CPU exhaustion** — force deserialization of massive payloads
- **Amplification attacks** — small request triggers large response

### Vulnerable Code (No Message Size Limits)

```go
// VULNERABLE: Default max message size is 4MB — still vulnerable
// But allowing unlimited custom sizes:
s := grpc.NewServer() // Default limits can be bypassed

// Client side with no receive limit
conn, _ := grpc.Dial(address, grpc.WithInsecure())
// Client can receive arbitrarily large responses
client := pb.NewServiceClient(conn)
```

### Secure Code (Strict Message Size Limits)

```go
// SECURE: Enforce message size limits on both server and client
package main

// Server side
s := grpc.NewServer(
    grpc.MaxRecvMsgSize(4 * 1024 * 1024),     // 4MB max receive
    grpc.MaxSendMsgSize(1 * 1024 * 1024),     // 1MB max send
)

// Client side
conn, err := grpc.Dial(address,
    grpc.WithTransportCredentials(creds),
    grpc.WithDefaultCallOptions(
        grpc.MaxCallRecvMsgSize(4 * 1024 * 1024),
        grpc.MaxCallSendMsgSize(1 * 1024 * 1024),
    ),
)
```

---