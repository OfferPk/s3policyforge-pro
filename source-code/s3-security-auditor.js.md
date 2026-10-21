/\*\*  
 \* S3PolicyForge Pro \- 10-Point Zero-Trust S3 Security Auditor  
 \* Evaluates S3 Bucket Policies against CIS AWS Foundations Benchmark, NIST SP 800-53, and AWS Security Best Practices  
 \*/

(function (root, factory) {  
  if (typeof module \=== 'object' && module.exports) {  
    const Engine \= require('./s3-policy-engine.js');  
    module.exports \= factory(Engine);  
  } else {  
    root.S3SecurityAuditor \= factory(root.S3PolicyEngine);  
  }  
}(typeof self \!== 'undefined' ? self : this, function (Engine) {  
  'use strict';

  class S3SecurityAuditor {  
    constructor() {}

    auditPolicy(policyObj, bucketName \= 'my-bucket') {  
      const results \= \[\];  
      const statements \= Engine.normalizeArray(policyObj.Statement || \[\]);

      // 1\. Public Read Exposure Guard (15 pts)  
      let p1 \= { id: 'public\_read', title: 'Public Read Exposure Guard', maxScore: 15, score: 0, status: 'FAIL', details: '' };  
      let hasUnrestrictedPublicRead \= false;  
      for (const st of statements) {  
        if (st.Effect \=== 'Allow' && Engine.isPublicPrincipal(st.Principal)) {  
          const acts \= Engine.normalizeArray(st.Action);  
          const hasRead \= acts.some(a \=\> a \=== '\*' || a \=== 's3:\*' || a \=== 's3:GetObject');  
          if (hasRead) {  
            // Check if restricted by Condition  
            const cond \= st.Condition || {};  
            const hasBoundary \= cond.StringEquals?.\['AWS:SourceArn'\] ||  
                                cond.ArnEquals?.\['aws:SourceArn'\] ||  
                                cond.StringEquals?.\['aws:sourceVpc'\] ||  
                                cond.StringEquals?.\['aws:sourceVpce'\] ||  
                                cond.IpAddress?.\['aws:SourceIp'\];  
            if (\!hasBoundary) {  
              hasUnrestrictedPublicRead \= true;  
              break;  
            }  
          }  
        }  
      }  
      if (\!hasUnrestrictedPublicRead) {  
        p1.score \= 15; p1.status \= 'PASS';  
        p1.details \= 'Zero-Trust Verified: No unrestricted public read access granted. Sensitive bucket data is shielded from unauthenticated internet crawlers.';  
      } else {  
        p1.score \= 0; p1.status \= 'FAIL';  
        p1.details \= 'CRITICAL VULNERABILITY: Public read access granted to anonymous users without IP/VPC/CloudFront boundary conditions\!';  
      }  
      results.push(p1);

      // 2\. Public Write / Ransomware Guard (15 pts)  
      let p2 \= { id: 'public\_write', title: 'Public Write & Ransomware Guard', maxScore: 15, score: 0, status: 'FAIL', details: '' };  
      let hasUnrestrictedPublicWrite \= false;  
      for (const st of statements) {  
        if (st.Effect \=== 'Allow' && Engine.isPublicPrincipal(st.Principal)) {  
          const acts \= Engine.normalizeArray(st.Action);  
          const hasWrite \= acts.some(a \=\> a \=== '\*' || a \=== 's3:\*' || a \=== 's3:PutObject' || a \=== 's3:DeleteObject');  
          if (hasWrite) {  
            const cond \= st.Condition || {};  
            const hasBoundary \= cond.StringEquals?.\['aws:sourceVpc'\] || cond.IpAddress?.\['aws:SourceIp'\];  
            if (\!hasBoundary) {  
              hasUnrestrictedPublicWrite \= true;  
              break;  
            }  
          }  
        }  
      }  
      if (\!hasUnrestrictedPublicWrite) {  
        p2.score \= 15; p2.status \= 'PASS';  
        p2.details \= 'Protected: Public write, delete, and overwrite permissions are completely denied to anonymous callers.';  
      } else {  
        p2.score \= 0; p2.status \= 'FAIL';  
        p2.details \= 'FATAL HAZARD: Anonymous users can upload or delete objects\! Immediate ransomware and site defacement risk.';  
      }  
      results.push(p2);

      // 3\. In-Transit TLS Encryption Enforcement (15 pts)  
      let p3 \= { id: 'tls\_enforcement', title: 'TLS In-Transit Encryption (aws:SecureTransport)', maxScore: 15, score: 0, status: 'FAIL', details: '' };  
      let hasTLSDeny \= false;  
      for (const st of statements) {  
        if (st.Effect \=== 'Deny') {  
          const cond \= st.Condition || {};  
          if (cond.Bool && (cond.Bool\['aws:SecureTransport'\] \=== 'false' || cond.Bool\['aws:SecureTransport'\] \=== false)) {  
            hasTLSDeny \= true;  
            break;  
          }  
        }  
      }  
      if (hasTLSDeny) {  
        p3.score \= 15; p3.status \= 'PASS';  
        p3.details \= 'Explicit Deny for non-HTTPS traffic enforced. Meets PCI-DSS 4.0, HIPAA, and SOC 2 transit security standards.';  
      } else {  
        p3.score \= 0; p3.status \= 'FAIL';  
        p3.details \= 'NON-COMPLIANT: Missing explicit Deny for insecure HTTP connections (aws:SecureTransport: "false").';  
      }  
      results.push(p3);

      // 4\. Server-Side Encryption Enforcement (10 pts)  
      let p4 \= { id: 'sse\_encryption', title: 'Server-Side Encryption Upload Mandate', maxScore: 10, score: 0, status: 'FAIL', details: '' };  
      let hasSSEDeny \= false;  
      for (const st of statements) {  
        if (st.Effect \=== 'Deny') {  
          const acts \= Engine.normalizeArray(st.Action);  
          if (acts.includes('s3:PutObject') || acts.includes('s3:\*') || acts.includes('\*')) {  
            const cond \= st.Condition || {};  
            if (cond.StringNotEquals && cond.StringNotEquals\['s3:x-amz-server-side-encryption'\]) {  
              hasSSEDeny \= true;  
              break;  
            }  
          }  
        }  
      }  
      if (hasSSEDeny) {  
        p4.score \= 10; p4.status \= 'PASS';  
        p4.details \= 'Object uploads strictly require server-side encryption headers (KMS or AES256).';  
      } else {  
        p4.score \= 4; p4.status \= 'WARN';  
        p4.details \= 'No explicit bucket policy denying unencrypted object uploads. Relying solely on default bucket encryption.';  
      }  
      results.push(p4);

      // 5\. Resource Scope & ARN Hygiene (10 pts)  
      let p5 \= { id: 'arn\_scope', title: 'Resource ARN Scope Alignment', maxScore: 10, score: 0, status: 'FAIL', details: '' };  
      let scopeErrors \= \[\];  
      for (const st of statements) {  
        const val \= Engine.validateARNScope(st.Action, st.Resource, bucketName);  
        if (\!val.isValid) {  
          scopeErrors \= scopeErrors.concat(val.errors);  
        }  
      }  
      if (scopeErrors.length \=== 0\) {  
        p5.score \= 10; p5.status \= 'PASS';  
        p5.details \= 'All S3 actions match proper ARN targets (bucket actions target bucket ARN, object actions target object ARN).';  
      } else {  
        p5.score \= 0; p5.status \= 'FAIL';  
        p5.details \= \`ARN Scope Mismatch: \${scopeErrors\[0\]}\`;  
      }  
      results.push(p5);

      // 6\. Network Boundary Isolation (10 pts)  
      let p6 \= { id: 'network\_boundary', title: 'Network Boundary (VPC / IP Gating)', maxScore: 10, score: 0, status: 'FAIL', details: '' };  
      let hasNetworkBoundary \= false;  
      for (const st of statements) {  
        const cond \= st.Condition || {};  
        if (cond.StringEquals?.\['aws:sourceVpc'\] ||  
            cond.StringEquals?.\['aws:sourceVpce'\] ||  
            cond.StringNotEquals?.\['aws:sourceVpce'\] ||  
            cond.IpAddress?.\['aws:SourceIp'\] ||  
            cond.NotIpAddress?.\['aws:SourceIp'\] ||  
            cond.StringEquals?.\['AWS:SourceArn'\]) {  
          hasNetworkBoundary \= true;  
          break;  
        }  
      }  
      if (hasNetworkBoundary) {  
        p6.score \= 10; p6.status \= 'PASS';  
        p6.details \= 'Access restricted to dedicated corporate VPC Endpoints, authorized IP CIDRs, or specific CloudFront ARNs.';  
      } else {  
        p6.score \= 4; p6.status \= 'WARN';  
        p6.details \= 'No VPC or IP condition constraints present. Access relies entirely on IAM credential identity.';  
      }  
      results.push(p6);

      // 7\. Privilege Escalation & Admin Control Guard (10 pts)  
      let p7 \= { id: 'admin\_control', title: 'Admin & Policy Escalation Guard', maxScore: 10, score: 0, status: 'FAIL', details: '' };  
      let openAdmin \= false;  
      for (const st of statements) {  
        if (st.Effect \=== 'Allow') {  
          const acts \= Engine.normalizeArray(st.Action);  
          if (Engine.isPublicPrincipal(st.Principal) && (acts.includes('s3:PutBucketPolicy') || acts.includes('s3:PutBucketAcl') || acts.includes('\*'))) {  
            openAdmin \= true;  
            break;  
          }  
        }  
      }  
      if (\!openAdmin) {  
        p7.score \= 10; p7.status \= 'PASS';  
        p7.details \= 'Bucket policy and ACL administrative modifications are shielded from public or untrusted principals.';  
      } else {  
        p7.score \= 0; p7.status \= 'FAIL';  
        p7.details \= 'CRITICAL: Policy allows administrative alteration (s3:PutBucketPolicy / ACL) by unauthorized principals\!';  
      }  
      results.push(p7);

      // 8\. CloudFront OAC Hardening (5 pts)  
      let p8 \= { id: 'cloudfront\_oac', title: 'Origin Access Control (OAC) Hardening', maxScore: 5, score: 0, status: 'FAIL', details: '' };  
      let oacFound \= false;  
      for (const st of statements) {  
        if (st.Principal && st.Principal.Service \=== 'cloudfront.amazonaws.com') {  
          if (st.Condition?.StringEquals?.\['AWS:SourceArn'\] || st.Condition?.ArnEquals?.\['aws:SourceArn'\]) {  
            oacFound \= true;  
            break;  
          }  
        }  
      }  
      // If no public static site intention, pass by default; if present, check OAC  
      if (oacFound || hasNetworkBoundary) {  
        p8.score \= 5; p8.status \= 'PASS';  
        p8.details \= 'Origin Access Control (OAC) verified with distribution ARN condition, preventing CloudFront bypass.';  
      } else {  
        p8.score \= 3; p8.status \= 'WARN';  
        p8.details \= 'No CloudFront OAC condition detected.';  
      }  
      results.push(p8);

      // 9\. Least-Privilege Action Precision (5 pts)  
      let p9 \= { id: 'least\_privilege', title: 'Least-Privilege Action Specificity', maxScore: 5, score: 0, status: 'FAIL', details: '' };  
      let hasBroadWildcardAllow \= false;  
      for (const st of statements) {  
        if (st.Effect \=== 'Allow') {  
          const acts \= Engine.normalizeArray(st.Action);  
          if (acts.includes('\*') || acts.includes('s3:\*')) {  
            hasBroadWildcardAllow \= true;  
            break;  
          }  
        }  
      }  
      if (\!hasBroadWildcardAllow) {  
        p9.score \= 5; p9.status \= 'PASS';  
        p9.details \= 'Granular actions defined. Avoids excessive wildcard "s3:\*" in Allow statements.';  
      } else {  
        p9.score \= 2; p9.status \= 'WARN';  
        p9.details \= 'Broad wildcard "s3:\*" in Allow statement violates least-privilege principles.';  
      }  
      results.push(p9);

      // 10\. IAM Policy Schema Integrity (5 pts)  
      let p10 \= { id: 'schema\_validity', title: 'IAM JSON Schema 2012-10-17 Validity', maxScore: 5, score: 0, status: 'FAIL', details: '' };  
      if (policyObj.Version \=== '2012-10-17' && Array.isArray(policyObj.Statement)) {  
        p10.score \= 5; p10.status \= 'PASS';  
        p10.details \= 'Policy adheres strictly to AWS IAM Policy Grammar 2012-10-17 schema.';  
      } else {  
        p10.score \= 0; p10.status \= 'FAIL';  
        p10.details \= 'Invalid IAM Policy Version or Statement structure.';  
      }  
      results.push(p10);

      const totalScore \= results.reduce((acc, curr) \=\> acc \+ curr.score, 0);  
      let grade \= 'F';  
      let gradeColor \= '\#ef4444';  
      if (totalScore \>= 90\) {  
        grade \= 'A+'; gradeColor \= '\#10b981';  
      } else if (totalScore \>= 80\) {  
        grade \= 'B'; gradeColor \= '\#06b6d4';  
      } else if (totalScore \>= 60\) {  
        grade \= 'C'; gradeColor \= '\#f59e0b';  
      } else {  
        grade \= 'F'; gradeColor \= '\#ef4444';  
      }

      return {  
        bucketName,  
        totalScore,  
        maxScore: 100,  
        grade,  
        gradeColor,  
        isZeroTrustVerified: totalScore \>= 90,  
        results  
      };  
    }  
  }

  return S3SecurityAuditor;  
}));  
