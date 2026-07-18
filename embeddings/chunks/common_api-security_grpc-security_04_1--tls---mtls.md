---
source: "common/api-security/grpc-security.md"
title: "gRPC Security"
heading: "1. TLS & mTLS"
category: "api-security"
language: "common"
severity: "medium"
tags: [api-security, message, mtls, overview, reflection, size, table]
chunk: 4/9
---

## 1. TLS & mTLS

gRPC mandates HTTP/2, and TLS is strongly recommended for all production deployments. The absence of TLS exposes:

- **Data in transit** — protobuf messages transmitted in cleartext
- **Man-in-the-middle** — injection/modification of RPC calls
- **Identity spoofing** — no server identity verification

### Vulnerable Code (No TLS)

```go
// VULNERABLE: gRPC server without TLS
package main

import (
    "google.golang.org/grpc"
)

func main() {
    lis, _ := net.Listen("tcp", ":50051")
    
    // No TLS options — all traffic in cleartext!
    s := grpc.NewServer()
    pb.RegisterUserServiceServer(s, &userServer{})
    s.Serve(lis)
}
```

### Secure Code (TLS with mTLS)

```go
// SECURE: gRPC server with mTLS
package main

import (
    "crypto/tls"
    "crypto/x509"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials"
)

func main() {
    // Load server certificate and key
    serverCert, _ := tls.LoadX509KeyPair("server.crt", "server.key")
    
    // Load CA certificate for client verification
    caCert, _ := os.ReadFile("ca.crt")
    caPool := x509.NewCertPool()
    caPool.AppendCertsFromPEM(caCert)
    
    tlsConfig := &tls.Config{
        Certificates: []tls.Certificate{serverCert},
        ClientAuth:   tls.RequireAndVerifyClientCert, // mTLS
        ClientCAs:    caPool,
        MinVersion:   tls.VersionTLS13, // Require modern TLS
    }
    
    s := grpc.NewServer(
        grpc.Creds(credentials.NewTLS(tlsConfig)),
    )
    pb.RegisterUserServiceServer(s, &userServer{})
    s.Serve(lis)
}
```

---