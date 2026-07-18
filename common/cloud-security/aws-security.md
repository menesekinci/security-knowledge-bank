# AWS Security

> **Category:** Common / Cloud Security
> **Last Updated:** July 2026

## Overview

Amazon Web Services (AWS) is the largest cloud provider, and its security misconfigurations are a leading cause of data breaches. This document covers IAM least privilege, S3 bucket policies, Lambda security, API Gateway authentication, and AWS-specific CVE examples.

---

## Table of Contents

1. [IAM Least Privilege](#1-iam-least-privilege)
2. [S3 Bucket Policies](#2-s3-bucket-policies)
3. [Lambda Security](#3-lambda-security)
4. [API Gateway Authentication](#4-api-gateway-authentication)
5. [CVEs & Real-World Examples](#5-cves--real-world-examples)

---

## 1. IAM Least Privilege

IAM is the core of AWS security. Overly permissive IAM policies effect the majority of AWS breaches.

### Vulnerable IAM Policy (AdministratorAccess)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",  // Wildcard — ALL actions!
      "Resource": "*" // ALL resources!
    }
  ]
}
```

### Secure IAM Policy (Least Privilege)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "S3ReadSpecificBucket",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::my-app-data",
        "arn:aws:s3:::my-app-data/*"
      ],
      "Condition": {
        "StringEquals": {
          "aws:SourceIp": "10.0.0.0/16"
        }
      }
    },
    {
      "Sid": "S3DenyDelete",
      "Effect": "Deny",
      "Action": "s3:DeleteObject",
      "Resource": "arn:aws:s3:::my-app-data/*"
    }
  ]
}
```

### Secure IAM Role for Lambda

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:*:*:*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "dynamodb:GetItem",
        "dynamodb:Query"
      ],
      "Resource": "arn:aws:dynamodb:us-east-1:123456789012:table/Users"
    }
  ]
}
```

### IAM Policy Validation Commands

```bash
# Use IAM Access Analyzer to validate policies
aws accessanalyzer validate-policy \
  --policy-document file://policy.json \
  --policy-type IDENTITY_POLICY

# Check for unused permissions
aws iam get-service-last-accessed-details \
  --arn arn:aws:iam::123456789012:user/my-user
```

---

## 2. S3 Bucket Policies

Publicly accessible S3 buckets remain a leading cause of data leaks.

### Vulnerable S3 Bucket (Public Read)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",       // ANYONE on the internet
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::my-company-data/*"
    }
  ]
}
```

### Secure S3 Bucket Policies

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyPublicRead",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::my-company-data/*",
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "false"
        }
      }
    },
    {
      "Sid": "DenyInsecureConnections",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::my-company-data/*",
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "false"
        }
      }
    }
  ]
}
```

### Block Public Access (Account Level)

```bash
# Block ALL public access at account level
aws s3control put-public-access-block \
  --account-id 123456789012 \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# Audit all buckets for public access
aws s3api list-buckets --query 'Buckets[*].Name' --output text | \
  xargs -I {} sh -c 'aws s3api get-public-access-block --bucket {} 2>/dev/null || echo "No block on {}"'
```

---

## 3. Lambda Security

Lambda functions are ephemeral but still vulnerable to injection, overprivileged execution roles, and sensitive data exposure.

### Vulnerable Lambda (Command Injection)

```python
# VULNERABLE: Shell command injection via user input
import subprocess
import json

def lambda_handler(event, context):
    user_input = event['queryStringParameters']['filename']
    
    # Command injection! User passes "; rm -rf /"
    result = subprocess.check_output(f"cat /tmp/{user_input}", shell=True)
    
    return {
        'statusCode': 200,
        'body': result.decode()
    }
```

### Secure Lambda (Parameterized)

```python
# SECURE: No shell execution; validate inputs; least privilege
import json
import os
import boto3

s3 = boto3.client('s3')

ALLOWED_FILES = {'report1.pdf', 'report2.pdf', 'summary.csv'}

def lambda_handler(event, context):
    filename = event['queryStringParameters'].get('filename', '')
    
    # Validate filename against allow list
    if filename not in ALLOWED_FILES:
        return {
            'statusCode': 403,
            'body': json.dumps({'error': 'File not allowed'})
        }
    
    # Use S3 API, not shell commands
    try:
        response = s3.get_object(
            Bucket=os.environ.get('REPORT_BUCKET'),
            Key=f"reports/{filename}"
        )
        content = response['Body'].read().decode('utf-8')
        
        return {
            'statusCode': 200,
            'body': content
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }
```

### Secure Lambda Configuration

```yaml
# AWS SAM template with security best practices
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  SecureFunction:
    Type: AWS::Serverless::Function
    Properties:
      CodeUri: src/
      Handler: app.handler
      Runtime: python3.11
      # Use IAM role with least privilege
      Policies:
        - DynamoDBReadPolicy:
            TableName: MyTable
        - S3ReadPolicy:
            BucketName: my-app-data
      Environment:
        Variables:
          REPORT_BUCKET: my-app-data
      # VPC configuration for network isolation
      VpcConfig:
        SecurityGroupIds:
          - !Ref LambdaSecurityGroup
        SubnetIds:
          - subnet-12345
      # Reserved concurrency prevents resource exhaustion
      ReservedConcurrentExecutions: 10
```

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

## 5. CVEs & Real-World Examples

### CVE-2025-14764 — Amazon S3 Encryption Client Key Confusion
- **Description**: Missing cryptographic key commitment in the Amazon S3 Encryption Client for Go. A user with write access to the S3 bucket could introduce a new encryption data key (EDK) that decrypts to different plaintext — effectively a key confusion attack
- **Affected**: Amazon S3 Encryption Client for Go, .NET
- **CVSS**: 7.4 (High)
- **Fix**: Upgrade to versions with cryptographic key commitment support
- **Source**: https://nvd.nist.gov/vuln/detail/CVE-2025-14764

### CVE-2025-23206 — AWS CDK IAM OIDC Provider MITM (Unverified TLS)
- **Description**: The AWS CDK IAM OIDC custom-resource provider downloads the identity provider's CA thumbprint using `tls.connect` with `rejectUnauthorized: false` hardcoded. Because the TLS certificate is never validated, a man-in-the-middle can impersonate the OIDC provider and have the CA thumbprint pinned to an attacker-controlled endpoint. (Not "information disclosure in template outputs" — the earlier write-up was wrong.)
- **Affected**: `aws-cdk-lib` before 2.177.0 (IAM OIDC custom-resource provider)
- **CVSS**: Low — the AWS CDK advisory (CNA, GHSA-v4mq-x674-ff73) rates it CVSS 4.0 = 1.8 Low, because the issuer URL is defined by the CDK author and the code runs inside a Lambda environment that mitigates MITM. (NVD adopted an inflated 8.1 High primary score; CWE-347, Improper Verification of Cryptographic Signature.)
- **Fix**: Upgrade to CDK ≥ 2.177.0 and set the feature flag `@aws-cdk/aws-iam:oidcRejectUnauthorizedConnections` to `true` in `cdk.json`/`cdk.context.json`
- **Source**: https://github.com/aws/aws-cdk/security/advisories/GHSA-v4mq-x674-ff73

### Public S3 Bucket Data Leak — "AWS S3 Bucket Slippage" (Ongoing)
- **Description**: Continual stream of data breaches from misconfigured S3 buckets. In 2025 alone, over 200 million records were exposed through publicly accessible S3 buckets. Notable examples include healthcare records, voter databases, and internal source code
- **Fix**: Enable S3 Block Public Access at account level; use AWS Config rules to detect and auto-remediate public buckets
- **Source**: https://docs.prismacloud.io/en/enterprise-edition/rn/prisma-cloud-release-info/features-introduced-in-2025/features-introduced-in-february-2025

### CISA AWS GovCloud Key Leak (2025)
- **Description**: A CISA administrator leaked AWS GovCloud plaintext credentials on GitHub via a private repository that should have been .gitignored. The exposed keys gave access to critical CISA GovCloud resources
- **Impact**: Sensitive government cloud infrastructure potentially compromised
- **Fix**: Enforce git-secrets scanning; use IAM Access Analyzer; rotate credentials immediately upon discovery
- **Source**: https://krebsonsecurity.com/2026/05/cisa-admin-leaked-aws-govcloud-keys-on-github/

### AWS Lambda Command Injection (Common Bug Bounty Finding)
- **Description**: Lambda functions that construct shell commands from event parameters are a common high-severity bug bounty finding. Even when input validation appears solid, edge cases in shell quoting and parameter expansion can bypass filters
- **Fix**: Never use `shell=True` in subprocess calls; use SDKs instead of shell commands; validate all inputs against an allow list
- **Source**: https://docs.aws.amazon.com/lambda/latest/dg/best-practices.html

### CVE-2025-4802 — glibc `LD_LIBRARY_PATH` Untrusted Search Path (setuid dlopen)
- **Description**: An untrusted `LD_LIBRARY_PATH` environment-variable vulnerability in the GNU C Library (glibc). In statically-compiled **setuid** binaries that call `dlopen` (including internal `dlopen` calls after `setlocale` or NSS functions), an attacker-controlled `LD_LIBRARY_PATH` can force loading of an attacker-supplied shared library, leading to local privilege escalation. This is a glibc flaw — it surfaces in Lambda/container base images only because they ship the affected glibc, not a Lambda-specific bug.
- **Affected**: glibc 2.27 through 2.38 (shipped by many Linux base images, including some Lambda/container runtimes)
- **CVSS**: 7.8 (High) — CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H (CWE-426, Untrusted Search Path)
- **Fix**: Patch glibc (≥ 2.39, or distro backports); rebuild container/Lambda images against patched base images; use image scanning
- **Source**: https://nvd.nist.gov/vuln/detail/CVE-2025-4802

---

## References

- [AWS Security Documentation](https://docs.aws.amazon.com/security/)
- [AWS IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [AWS S3 Security](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security.html)
- [AWS Lambda Security Best Practices](https://docs.aws.amazon.com/lambda/latest/dg/best-practices.html)
- [Amazon Linux Security Center — CVE List](https://explore.alas.aws.amazon.com/)
- [SentinelOne — AWS CDK Vulnerability CVE-2025-23206](https://www.sentinelone.com/vulnerability-database/cve-2025-23206/)
- [Krebs on Security — CISA GovCloud Key Leak](https://krebsonsecurity.com/2026/05/cisa-admin-leaked-aws-govcloud-keys-on-github/)
