---
source: "common/cloud-security/aws-security.md"
title: "AWS Security"
heading: "2. S3 Bucket Policies"
category: "cloud-security"
language: "common"
severity: "medium"
tags: [bucket, cloud-security, lambda, least, overview, security, table]
chunk: 5/9
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