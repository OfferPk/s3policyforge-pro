/\*\*  
 \* S3PolicyForge Pro \- Policy Grammar & ARN Scope Engine  
 \* AWS IAM Policy JSON 2012-10-17 / CIS AWS Foundations Benchmark Compliant  
 \*/

(function (root, factory) {  
  if (typeof module \=== 'object' && module.exports) {  
    module.exports \= factory();  
  } else {  
    root.S3PolicyEngine \= factory();  
  }  
}(typeof self \!== 'undefined' ? self : this, function () {  
  'use strict';

  // Action Scope Categorization  
  const BUCKET\_LEVEL\_ACTIONS \= \[  
    's3:ListBucket',  
    's3:ListBucketVersions',  
    's3:ListBucketMultipartUploads',  
    's3:GetBucketLocation',  
    's3:GetBucketAcl',  
    's3:PutBucketAcl',  
    's3:GetBucketPolicy',  
    's3:PutBucketPolicy',  
    's3:DeleteBucketPolicy',  
    's3:GetBucketNotification',  
    's3:PutBucketNotification',  
    's3:GetBucketLogging',  
    's3:PutBucketLogging',  
    's3:GetLifecycleConfiguration',  
    's3:PutLifecycleConfiguration',  
    's3:GetEncryptionConfiguration',  
    's3:PutEncryptionConfiguration',  
    's3:GetBucketTagging',  
    's3:PutBucketTagging',  
    's3:GetBucketVersioning',  
    's3:PutBucketVersioning'  
  \];

  const OBJECT\_LEVEL\_ACTIONS \= \[  
    's3:GetObject',  
    's3:GetObjectVersion',  
    's3:GetObjectAcl',  
    's3:PutObjectAcl',  
    's3:PutObject',  
    's3:DeleteObject',  
    's3:DeleteObjectVersion',  
    's3:AbortMultipartUpload',  
    's3:ListMultipartUploadParts',  
    's3:RestoreObject'  
  \];

  const DANGEROUS\_WRITE\_ACTIONS \= \[  
    's3:PutObject',  
    's3:DeleteObject',  
    's3:DeleteObjectVersion',  
    's3:PutObjectAcl',  
    's3:PutBucketPolicy',  
    's3:DeleteBucketPolicy',  
    's3:PutBucketAcl'  
  \];

  function normalizeArray(val) {  
    if (\!val) return \[\];  
    if (Array.isArray(val)) return val;  
    return \[val\];  
  }

  function isPublicPrincipal(principal) {  
    if (\!principal) return false;  
    if (principal \=== '\*') return true;  
    if (typeof principal \=== 'object') {  
      if (principal.AWS \=== '\*' || principal.AWS \=== 'arn:aws:iam::\*:root') return true;  
      if (Array.isArray(principal.AWS) && (principal.AWS.includes('\*') || principal.AWS.includes('arn:aws:iam::\*:root'))) return true;  
    }  
    return false;  
  }

  function validateARNScope(actions, resources, bucketName) {  
    const actList \= normalizeArray(actions);  
    const resList \= normalizeArray(resources);  
    const bucketArn \= \`arn:aws:s3:::\${bucketName}\`;  
    const objectArn \= \`arn:aws:s3:::\${bucketName}/\*\`;

    const errors \= \[\];  
    const hasWildcardAction \= actList.includes('s3:\*') || actList.includes('\*');

    for (const a of actList) {  
      if (BUCKET\_LEVEL\_ACTIONS.includes(a)) {  
        const hasBucketArn \= resList.some(r \=\> r \=== bucketArn || r \=== '\*');  
        if (\!hasBucketArn) {  
          errors.push(\`Bucket-level action "\${a}" requires bucket ARN (\${bucketArn}), but only object ARNs were provided.\`);  
        }  
      }  
      if (OBJECT\_LEVEL\_ACTIONS.includes(a)) {  
        const hasObjectArn \= resList.some(r \=\> r \=== objectArn || r.startsWith(\`\${bucketArn}/\`) || r \=== '\*');  
        if (\!hasObjectArn) {  
          errors.push(\`Object-level action "\${a}" requires object ARN (\${objectArn}), but only the root bucket ARN was provided.\`);  
        }  
      }  
    }

    return {  
      isValid: errors.length \=== 0,  
      errors  
    };  
  }

  // Pre-configured Zero-Trust Security Statements  
  function createEnforceTLSDenyStatement(bucketName) {  
    return {  
      Sid: 'EnforceTLSRequestsOnly',  
      Effect: 'Deny',  
      Principal: '\*',  
      Action: 's3:\*',  
      Resource: \[  
        \`arn:aws:s3:::\${bucketName}\`,  
        \`arn:aws:s3:::\${bucketName}/\*\`  
      \],  
      Condition: {  
        Bool: {  
          'aws:SecureTransport': 'false'  
        }  
      }  
    };  
  }

  function createRequireKMSPutStatement(bucketName) {  
    return {  
      Sid: 'DenyUnencryptedObjectUploads',  
      Effect: 'Deny',  
      Principal: '\*',  
      Action: 's3:PutObject',  
      Resource: \`arn:aws:s3:::\${bucketName}/\*\`,  
      Condition: {  
        StringNotEquals: {  
          's3:x-amz-server-side-encryption': 'aws:kms'  
        }  
      }  
    };  
  }

  function createRestrictToVpcEndpointStatement(bucketName, vpcEndpointId) {  
    return {  
      Sid: 'RestrictAccessToVPCEndpoint',  
      Effect: 'Deny',  
      Principal: '\*',  
      Action: 's3:\*',  
      Resource: \[  
        \`arn:aws:s3:::\${bucketName}\`,  
        \`arn:aws:s3:::\${bucketName}/\*\`  
      \],  
      Condition: {  
        StringNotEquals: {  
          'aws:sourceVpce': vpcEndpointId  
        }  
      }  
    };  
  }

  function createCloudFrontOACStatement(bucketName, distributionArn) {  
    return {  
      Sid: 'AllowCloudFrontServicePrincipalReadOnly',  
      Effect: 'Allow',  
      Principal: {  
        Service: 'cloudfront.amazonaws.com'  
      },  
      Action: 's3:GetObject',  
      Resource: \`arn:aws:s3:::\${bucketName}/\*\`,  
      Condition: {  
        StringEquals: {  
          'AWS:SourceArn': distributionArn  
        }  
      }  
    };  
  }

  return {  
    BUCKET\_LEVEL\_ACTIONS,  
    OBJECT\_LEVEL\_ACTIONS,  
    DANGEROUS\_WRITE\_ACTIONS,  
    normalizeArray,  
    isPublicPrincipal,  
    validateARNScope,  
    createEnforceTLSDenyStatement,  
    createRequireKMSPutStatement,  
    createRestrictToVpcEndpointStatement,  
    createCloudFrontOACStatement  
  };  
}));  
