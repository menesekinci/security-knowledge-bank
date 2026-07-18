---
source: "common/api-security/grpc-security.md"
title: "gRPC Security"
heading: "4. Authentication Interceptors"
category: "api-security"
language: "common"
severity: "medium"
tags: [api-security, message, mtls, overview, reflection, size, table]
chunk: 7/9
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