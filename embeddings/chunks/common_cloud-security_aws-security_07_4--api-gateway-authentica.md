---
source: "common/cloud-security/aws-security.md"
title: "AWS Security"
heading: "4. API Gateway Authentication"
category: "cloud-security"
language: "common"
severity: "medium"
tags: [bucket, cloud-security, lambda, least, overview, security, table]
chunk: 7/9
---

## 4. API Gateway Authentication

API Gateway is commonly used to front AWS APIs. Missing or improper authentication exposes endpoints.

### Vulnerable API Gateway (No Auth)

```yaml
# VULNERABLE: REST API endpoint with no authentication
openapi: "3.0.1"
info:
  title: "Admin API"
paths:
  /admin/users:
    get:
      # No security block — publicly accessible
      x-amazon-apigateway-integration:
        uri: "arn:aws:lambda:us-east-1:123456789012:function:admin-function"
        httpMethod: "POST"
        type: "AWS_PROXY"
  /admin/delete-user:
    post:
      # No auth at all!
      x-amazon-apigateway-integration:
        uri: "arn:aws:lambda:us-east-1:123456789012:function:delete-user"
        httpMethod: "POST"
        type: "AWS_PROXY"
```

### Secure API Gateway (Cognito + IAM)

```yaml
# SECURE: API Gateway with Cognito user pool authorizer
openapi: "3.0.1"
info:
  title: "Secure Admin API"
paths:
  /admin/users:
    get:
      security:
        - CognitoAuth: []
      x-amazon-apigateway-integration:
        uri: "arn:aws:lambda:us-east-1:123456789012:function:admin-function"
        httpMethod: "POST"
        type: "AWS_PROXY"
  /public/status:
    get:
      # Public endpoint explicitly allowed (read-only health check)
      x-amazon-apigateway-integration:
        uri: "arn:aws:lambda:us-east-1:123456789012:function:health"
        httpMethod: "POST"
        type: "AWS_PROXY"

components:
  securitySchemes:
    CognitoAuth:
      type: apiKey
      name: Authorization
      in: header
      x-amazon-apigateway-authtype: cognito_user_pools
      x-amazon-apigateway-authorizer:
        type: cognito_user_pools
        providerARNs:
          - arn:aws:cognito-idp:us-east-1:123456789012:userpool/us-east-1_ABC123
```

### API Gateway Usage Plans & Rate Limiting

```yaml
# CloudFormation: API key + usage plan
UsagePlan:
  Type: AWS::ApiGateway::UsagePlan
  Properties:
    ApiStages:
      - ApiId: !Ref MyApi
        Stage: prod
    Throttle:
      BurstLimit: 100
      RateLimit: 50
    Quota:
      Limit: 10000
      Period: DAY

ApiKey:
  Type: AWS::ApiGateway::ApiKey
  Properties:
    Enabled: true
    StageKeys:
      - RestApiId: !Ref MyApi
        StageName: prod
```

---