---
source: "common/cloud-security/aws-security.md"
title: "AWS Security"
heading: "1. IAM Least Privilege"
category: "cloud-security"
language: "common"
severity: "medium"
tags: [bucket, cloud-security, lambda, least, overview, security, table]
chunk: 4/9
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