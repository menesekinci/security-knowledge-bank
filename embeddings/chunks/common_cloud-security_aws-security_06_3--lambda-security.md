---
source: "common/cloud-security/aws-security.md"
title: "AWS Security"
heading: "3. Lambda Security"
category: "cloud-security"
language: "common"
severity: "medium"
tags: [bucket, cloud-security, lambda, least, overview, security, table]
chunk: 6/9
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