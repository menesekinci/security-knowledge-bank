# gRPC Security

> **Category:** Common / API Security
> **Last Updated:** July 2026

## Overview

gRPC is a high-performance RPC framework widely used in microservice architectures. Its binary protocol, HTTP/2 transport, and protobuf serialization introduce security considerations distinct from REST. This document covers TLS/mTLS, reflection API risks, message size limits, authentication interceptors, and related CVEs.

---

## Table of Contents

1. [TLS & mTLS](#1-tls--mtls)
2. [Reflection API](#2-reflection-api)
3. [Message Size Limits](#3-message-size-limits)
4. [Authentication Interceptors](#4-authentication-interceptors)
5. [CVEs & Real-World Examples](#5-cves--real-world-examples)

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

## 2. Reflection API

gRPC Reflection allows clients to discover service definitions, methods, message types, and file descriptors at runtime. If left enabled in production, it provides attackers with the entire API surface.

### Vulnerable Code (Reflection Enabled in Production)

```go
// VULNERABLE: gRPC reflection exposed in production
import (
    "google.golang.org/grpc/reflection"
)

func main() {
    s := grpc.NewServer()
    pb.RegisterUserServiceServer(s, &userServer{})
    
    // Reflection exposes all service/method names!
    reflection.Register(s)
    
    s.Serve(lis)
}
```

### Secure Code (Disable Reflection or Restrict)

```go
// SECURE: Disable reflection in production
func main() {
    s := grpc.NewServer()
    pb.RegisterUserServiceServer(s, &userServer{})
    
    if os.Getenv("ENVIRONMENT") == "development" {
        // Only enable reflection in non-production environments
        reflection.Register(s)
    }
    
    s.Serve(lis)
}
```

```go
// SECURE: Alternative — intercept reflection with auth middleware
import (
    "google.golang.org/grpc/reflection"
    "google.golang.org/grpc/reflection/reflectionpb"
)

func unaryReflectionInterceptor(ctx context.Context, req interface{}, 
    info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
    
    // Block reflection requests from external clients
    if info.Server == (*reflectionpb.ServerReflection_Server)(nil) {
        if !isAdminClient(ctx) {
            return nil, status.Error(codes.PermissionDenied, "reflection restricted")
        }
    }
    return handler(ctx, req)
}
```

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

## 4. Authentication Interceptors

Authentication in gRPC should be implemented via interceptors (middleware), not duplicated in each handler.

### Vulnerable Code (No Auth Interceptor)

```go
// VULNERABLE: Each handler must remember to check auth
// Easy to forget — especially for new handlers
func (s *userServer) GetAdminData(ctx context.Context, 
    req *pb.AdminRequest) (*pb.AdminResponse, error) {
    
    // Developer forgot to check auth here!
    // Admin data exposed without authentication
    return &pb.AdminResponse{Secret: "super-secret-admin-key"}, nil
}
```

### Secure Code (Auth Interceptor)

```go
// SECURE: Centralized authentication interceptor
package main

import (
    "google.golang.org/grpc"
    "google.golang.org/grpc/codes"
    "google.golang.org/grpc/metadata"
    "google.golang.org/grpc/status"
)

// AuthInterceptor validates tokens on every request
type AuthInterceptor struct {
    jwtSecret string
}

func (interceptor *AuthInterceptor) Unary() grpc.UnaryServerInterceptor {
    return func(ctx context.Context, req interface{},
        info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
        
        // Skip auth for health check or reflection
        if info.FullMethod == "/grpc.health.v1.Health/Check" {
            return handler(ctx, req)
        }
        
        md, ok := metadata.FromIncomingContext(ctx)
        if !ok {
            return nil, status.Error(codes.Unauthenticated, "missing metadata")
        }
        
        token := extractToken(md["authorization"])
        if token == "" {
            return nil, status.Error(codes.Unauthenticated, "missing token")
        }
        
        claims, err := verifyJWT(token, interceptor.jwtSecret)
        if err != nil {
            return nil, status.Error(codes.Unauthenticated, "invalid token")
        }
        
        // Inject claims into context for downstream handlers
        newCtx := context.WithValue(ctx, "claims", claims)
        return handler(newCtx, req)
    }
}

func (interceptor *AuthInterceptor) Stream() grpc.StreamServerInterceptor {
    return func(srv interface{}, stream grpc.ServerStream,
        info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
        // Similar auth check for streaming RPCs
        md, ok := metadata.FromIncomingContext(stream.Context())
        if !ok {
            return status.Error(codes.Unauthenticated, "missing metadata")
        }
        // ... auth logic ...
        return handler(srv, stream)
    }
}

func main() {
    authInterceptor := &AuthInterceptor{jwtSecret: os.Getenv("JWT_SECRET")}
    
    s := grpc.NewServer(
        grpc.UnaryInterceptor(authInterceptor.Unary()),
        grpc.StreamInterceptor(authInterceptor.Stream()),
        grpc.MaxRecvMsgSize(4 * 1024 * 1024),
        grpc.MaxSendMsgSize(1 * 1024 * 1024),
        grpc.Creds(credentials.NewTLS(tlsConfig)),
    )
    pb.RegisterUserServiceServer(s, &userServer{})
    s.Serve(lis)
}
```

---

## 5. CVEs & Real-World Examples

### CVE-2024-11407 — gRPC-C++ Zero-Copy Data-Corruption DoS
- **Description**: On gRPC-C++ servers with transmit zero-copy enabled (`GRPC_ARG_TCP_TX_ZEROCOPY_ENABLED`), application data can be corrupted before transmission, so the receiver gets an incorrect byte set and RPC requests fail — a denial of service via data corruption (CWE-682 Incorrect Calculation, not a TLS/info-disclosure issue)
- **Affected**: gRPC-C++ with TCP TX zero-copy enabled
- **CVSS**: 6.9 (Medium, CVSS 4.0)
- **Fix**: Upgrade to a patched gRPC release
- **Source**: https://github.com/advisories/GHSA-p9rf-64qj-22rw

### gRPC Reflection Information Disclosure (Multiple Reports)
- **Description**: Numerous penetration tests and bug bounty reports cite enabled gRPC reflection in production as a critical finding. Attackers use grpcurl or similar tools to enumerate all available services, methods, and message schemas
- **Affected**: Any production gRPC service with reflection enabled
- **Fix**: Disable reflection in production; use service mesh (e.g., Istio) for internal discovery
- **Source**: https://www.stackhawk.com/blog/best-practices-for-grpc-security/

### GO-2024-2687 — gRPC Example Code HTTP/2 Vulnerability
- **Description**: Example code in zitadel-go v3 library was impacted by HTTP/2 protocol vulnerabilities that could lead to stream multiplexing attacks
- **Affected**: zitadel-go v3 library, gRPC-example components
- **CVSS**: 7.5 (High)
- **Fix**: Update to patched versions; avoid using example code in production without review
- **Source**: https://github.com/zitadel/zitadel-go/security/advisories/GHSA-qc6v-5g5m-8cw2

### CVE-2023-44487 — HTTP/2 Rapid Reset Attack
- **Description**: Rapid reset attack on HTTP/2 streams, affecting gRPC over HTTP/2. Allows attackers to send rapid stream resets causing DoS
- **Affected**: Multiple gRPC implementations (C-core, Go, Java)
- **CVSS**: 7.5 (High)
- **Fix**: Apply patches from gRPC ecosystem; limit stream reset rate; upgrade to fixed versions
- **Source**: https://nvd.nist.gov/vuln/detail/CVE-2023-44487

### gRPC Message Size DoS (No CVE — Common Pattern)
- **Description**: Without enforced message size limits, attackers send large protobuf messages causing OOM on server. Multiple bug bounty reports cite this as a common finding in gRPC services
- **Fix**: Enforce `MaxRecvMsgSize` and `MaxSendMsgSize` at server initialization
- **Source**: https://www.stackhawk.com/blog/best-practices-for-grpc-security/

---

## References

- [gRPC Official Security Documentation](https://grpc.io/docs/guides/auth/)
- [StackHawk — gRPC Security Best Practices](https://www.stackhawk.com/blog/best-practices-for-grpc-security/)
- [Escape — How to Secure gRPC APIs](https://escape.tech/blog/how-to-secure-grpc-apis/)
- [IBM PTC Security — gRPC Security Series](https://medium.com/@ibm_ptc_security/grpc-security-series-part-3-c92f3b687dd9)
- [Levo — gRPC API Security Testing Guide](https://www.levo.ai/resources/blogs/grpc-api-security-testing)
- [OpenCVE — gRPC CVE Database](https://app.opencve.io/cve/?vendor=grpc)
