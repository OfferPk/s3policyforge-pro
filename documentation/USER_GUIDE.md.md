\# S3PolicyForge Pro \- User Guide & DevSecOps Integration Manual

\#\# 1\. Web Studio Quickstart

1\. Open \`source-code/index.html\` in any web browser.  
2\. Select an industry preset from the top dropdown:  
   \- \*\*Enterprise Internal Data Lake (A+)\*\*: TLS enforced, VPC endpoint bound, KMS encryption required, zero public exposure.  
   \- \*\*Production CloudFront OAC Static Site (A+)\*\*: Locked strictly to CloudFront OAC distribution ARN.  
   \- \*\*Hazardous Public Write & Ransomware Risk (F)\*\*: Unfiltered wildcard read/write policy exposing critical vulnerabilities.  
3\. Review the \*\*10-Point Zero-Trust Scorecard\*\* to inspect compliance and security health.  
4\. Toggle security baselines (Enforce TLS, Require KMS, VPC Endpoint Gating, CloudFront OAC) to generate clean statements.  
5\. Switch between output formats:  
   \- \*\*AWS S3 JSON\*\*: Ready to paste into the AWS Management Console.  
   \- \*\*Terraform HCL\*\*: \`aws\_s3\_bucket\_policy\` and \`aws\_s3\_bucket\_public\_access\_block\` resources.  
   \- \*\*AWS CLI\*\*: One-line command with escaped JSON.  
   \- \*\*Cloudflare R2\*\*: Worker fetch handler.  
   \- \*\*MinIO\*\*: \`mc\` commands.

\---

\#\# 2\. DevSecOps CLI Tool (\`s3policyforge-cli.py\`)

The standalone Python CLI tool requires zero external dependencies and runs on Python 3.8+.

\#\#\# 2.1 Linting S3 Policies for Scope and Syntax Errors  
\`\`\`bash  
python3 build/s3policyforge-cli.py lint \--preset presets/enterprise-secure-internal-datalake.json  
\`\`\`  
Output:  
\`\`\`  
\[LINT PASSED\] Policy syntax and ARN scope targets are clean for bucket 'enterprise-analytics-vault'.  
\`\`\`

\#\#\# 2.2 Running CI/CD Pipeline Security Audits  
\`\`\`bash  
\# Clean production policy \-\> Exits code 0  
python3 build/s3policyforge-cli.py audit \--preset presets/enterprise-secure-internal-datalake.json \--strict

\# Insecure policy \-\> Exits code 1 (Pipeline Fails)  
python3 build/s3policyforge-cli.py audit \--preset presets/hazardous-public-write-ransomware.json \--strict  
\`\`\`

\#\#\# 2.3 Synthesizing Terraform HCL  
\`\`\`bash  
python3 build/s3policyforge-cli.py synthesize \--preset presets/enterprise-secure-internal-datalake.json \-f terraform  
\`\`\`

\---

\#\# 3\. GitHub Actions CI/CD Pipeline Template

Add this workflow to your infrastructure repository (\`.github/workflows/s3-security-gate.yml\`) to automatically validate S3 bucket policies before applying Terraform or CloudFormation:

\`\`\`yaml  
name: S3 Bucket Policy Zero-Trust CI/CD Gate

on:  
  pull\_request:  
    paths:  
      \- 'terraform/s3/\*\*'  
      \- 'policies/\*\*'  
      \- 'cloudformation/\*\*'

jobs:  
  s3-audit:  
    runs-on: ubuntu-latest  
    steps:  
      \- name: Checkout Code  
        uses: actions/checkout@v4

      \- name: Set up Python  
        uses: actions/setup-python@v5  
        with:  
          python-version: '3.11'

      \- name: Lint Policy ARN Scopes  
        run: |  
          python3 build/s3policyforge-cli.py lint \--preset presets/enterprise-secure-internal-datalake.json

      \- name: Audit Zero-Trust Compliance  
        run: |  
          python3 build/s3policyforge-cli.py audit \--preset presets/enterprise-secure-internal-datalake.json \--strict  
\`\`\`  
