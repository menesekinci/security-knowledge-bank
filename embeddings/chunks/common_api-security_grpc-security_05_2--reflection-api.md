---
source: "common/api-security/grpc-security.md"
title: "gRPC Security"
heading: "2. Reflection API"
category: "api-security"
language: "common"
severity: "medium"
tags: [api-security, message, mtls, overview, reflection, size, table]
chunk: 5/9
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