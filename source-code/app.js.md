/\*\*  
 \* S3PolicyForge Pro \- Application Controller  
 \* Handles UI interactions, live policy mutation, security audits, and multi-cloud synthesis  
 \*/

document.addEventListener('DOMContentLoaded', () \=\> {  
  const engine \= S3PolicyEngine;  
  const auditor \= new S3SecurityAuditor();  
  const synthesizer \= new S3ConfigSynthesizer();

  let activeTab \= 'json';  
  let currentPolicy \= null;  
  let currentBucketName \= 'enterprise-analytics-vault';

  // DOM Elements  
  const presetSelect \= document.getElementById('presetSelect');  
  const bucketNameInput \= document.getElementById('bucketNameInput');  
  const toggleTls \= document.getElementById('toggleTls');  
  const toggleKms \= document.getElementById('toggleKms');  
  const toggleVpce \= document.getElementById('toggleVpce');  
  const toggleOac \= document.getElementById('toggleOac');  
  const vpceInput \= document.getElementById('vpceInput');  
  const oacArnInput \= document.getElementById('oacArnInput');

  const statementListContainer \= document.getElementById('statementListContainer');  
  const scoreNum \= document.getElementById('scoreNum');  
  const scoreGrade \= document.getElementById('scoreGrade');  
  const scoreCircle \= document.getElementById('scoreCircle');  
  const scoreHeadline \= document.getElementById('scoreHeadline');  
  const scoreSubtitle \= document.getElementById('scoreSubtitle');  
  const checklistContainer \= document.getElementById('checklistContainer');  
  const synthesizerOutput \= document.getElementById('synthesizerOutput');

  const btnExportJSON \= document.getElementById('btnExportJSON');  
  const btnCopyConfig \= document.getElementById('btnCopyConfig');  
  const tabButtons \= document.querySelectorAll('.tab-btn');

  // Built-in presets for offline / file:// protocol  
  const PRESETS \= {  
    'enterprise-datalake': {  
      bucketName: 'enterprise-analytics-vault',  
      policy: {  
        Version: '2012-10-17',  
        Statement: \[  
          {  
            Sid: 'EnforceTLSRequestsOnly',  
            Effect: 'Deny',  
            Principal: '\*',  
            Action: 's3:\*',  
            Resource: \[  
              'arn:aws:s3:::enterprise-analytics-vault',  
              'arn:aws:s3:::enterprise-analytics-vault/\*'  
            \],  
            Condition: {  
              Bool: {  
                'aws:SecureTransport': 'false'  
              }  
            }  
          },  
          {  
            Sid: 'DenyAccessOutsideCorporateVPCEndpoint',  
            Effect: 'Deny',  
            Principal: '\*',  
            Action: 's3:\*',  
            Resource: \[  
              'arn:aws:s3:::enterprise-analytics-vault',  
              'arn:aws:s3:::enterprise-analytics-vault/\*'  
            \],  
            Condition: {  
              StringNotEquals: {  
                'aws:sourceVpce': 'vpce-0123456789abcdef0'  
              }  
            }  
          },  
          {  
            Sid: 'DenyUnencryptedUploads',  
            Effect: 'Deny',  
            Principal: '\*',  
            Action: 's3:PutObject',  
            Resource: 'arn:aws:s3:::enterprise-analytics-vault/\*',  
            Condition: {  
              StringNotEquals: {  
                's3:x-amz-server-side-encryption': 'aws:kms'  
              }  
            }  
          },  
          {  
            Sid: 'AllowAnalyticsRoleReadWrite',  
            Effect: 'Allow',  
            Principal: {  
              AWS: 'arn:aws:iam::123456789012:role/AnalyticsProcessingRole'  
            },  
            Action: \[  
              's3:GetObject',  
              's3:PutObject',  
              's3:ListBucket'  
            \],  
            Resource: \[  
              'arn:aws:s3:::enterprise-analytics-vault',  
              'arn:aws:s3:::enterprise-analytics-vault/\*'  
            \]  
          }  
        \]  
      }  
    },  
    'cloudfront-oac': {  
      bucketName: 'static-web-cdn-assets',  
      policy: {  
        Version: '2012-10-17',  
        Statement: \[  
          {  
            Sid: 'EnforceTLSRequestsOnly',  
            Effect: 'Deny',  
            Principal: '\*',  
            Action: 's3:\*',  
            Resource: \[  
              'arn:aws:s3:::static-web-cdn-assets',  
              'arn:aws:s3:::static-web-cdn-assets/\*'  
            \],  
            Condition: {  
              Bool: {  
                'aws:SecureTransport': 'false'  
              }  
            }  
          },  
          {  
            Sid: 'AllowCloudFrontServicePrincipalReadOnly',  
            Effect: 'Allow',  
            Principal: {  
              Service: 'cloudfront.amazonaws.com'  
            },  
            Action: 's3:GetObject',  
            Resource: 'arn:aws:s3:::static-web-cdn-assets/\*',  
            Condition: {  
              StringEquals: {  
                'AWS:SourceArn': 'arn:aws:cloudfront::123456789012:distribution/EDFDVBD632BHYS5'  
              }  
            }  
          }  
        \]  
      }  
    },  
    'hazardous-ransomware': {  
      bucketName: 'unsecured-company-backups',  
      policy: {  
        Version: '2012-10-17',  
        Statement: \[  
          {  
            Sid: 'AllowAllInternetUsersFullReadWrite',  
            Effect: 'Allow',  
            Principal: '\*',  
            Action: \[  
              's3:GetObject',  
              's3:PutObject',  
              's3:DeleteObject',  
              's3:PutBucketPolicy'  
            \],  
            Resource: \[  
              'arn:aws:s3:::unsecured-company-backups',  
              'arn:aws:s3:::unsecured-company-backups/\*'  
            \]  
          }  
        \]  
      }  
    }  
  };

  function loadPreset(key) {  
    if (PRESETS\[key\]) {  
      const p \= JSON.parse(JSON.stringify(PRESETS\[key\]));  
      currentBucketName \= p.bucketName;  
      currentPolicy \= p.policy;  
      bucketNameInput.value \= currentBucketName;  
      syncTogglesFromPolicy();  
      recalculateAndRender();  
    }  
  }

  function syncTogglesFromPolicy() {  
    const stmts \= currentPolicy.Statement || \[\];  
    toggleTls.checked \= stmts.some(s \=\> s.Effect \=== 'Deny' && s.Condition?.Bool?.\['aws:SecureTransport'\]);  
    toggleKms.checked \= stmts.some(s \=\> s.Effect \=== 'Deny' && s.Condition?.StringNotEquals?.\['s3:x-amz-server-side-encryption'\]);  
    toggleVpce.checked \= stmts.some(s \=\> s.Effect \=== 'Deny' && s.Condition?.StringNotEquals?.\['aws:sourceVpce'\]);  
    toggleOac.checked \= stmts.some(s \=\> s.Principal?.Service \=== 'cloudfront.amazonaws.com');  
  }

  function recalculateAndRender() {  
    // 1\. Render Active Statements List  
    statementListContainer.innerHTML \= '';  
    const stmts \= currentPolicy.Statement || \[\];  
    stmts.forEach((s, idx) \=\> {  
      const el \= document.createElement('div');  
      el.style.background \= '\#080c1a';  
      el.style.border \= '1px solid var(--border-color)';  
      el.style.borderRadius \= '6px';  
      el.style.padding \= '8px 12px';

      const effectColor \= s.Effect \=== 'Deny' ? '\#ef4444' : '\#10b981';  
      const princ \= typeof s.Principal \=== 'string' ? s.Principal : JSON.stringify(s.Principal);  
      const acts \= Array.isArray(s.Action) ? s.Action.join(', ') : s.Action;

      el.innerHTML \= \`  
        \<div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;"\>  
          \<strong style="font-size:12px; color:var(--text-main);"\>\${s.Sid || 'Statement \#' \+ (idx \+ 1)}\</strong\>  
          \<span style="font-family:var(--font-mono); font-size:10px; font-weight:700; color:\${effectColor}; background:\${effectColor}22; padding:1px 6px; border-radius:4px;"\>\${s.Effect.toUpperCase()}\</span\>  
        \</div\>  
        \<div style="font-size:11px; color:var(--text-muted); font-family:var(--font-mono);"\>  
          \<div\>Principal: \<span style="color:var(--accent-cyan);"\>\${princ}\</span\>\</div\>  
          \<div\>Action: \<span style="color:\#f8fafc;"\>\${acts}\</span\>\</div\>  
        \</div\>  
      \`;  
      statementListContainer.appendChild(el);  
    });

    // 2\. Run 10-Point Security Audit  
    const audit \= auditor.auditPolicy(currentPolicy, currentBucketName);  
    renderScorecard(audit);

    // 3\. Render Synthesizer  
    renderSynthesizer();  
  }

  function renderScorecard(audit) {  
    scoreNum.textContent \= audit.totalScore;  
    scoreGrade.textContent \= audit.grade;  
    scoreCircle.style.borderColor \= audit.gradeColor;  
    scoreNum.style.color \= audit.gradeColor;

    if (audit.grade \=== 'A+') {  
      scoreHeadline.textContent \= 'Zero-Trust Verified • Production Ready';  
      scoreHeadline.style.color \= '\#10b981';  
      scoreSubtitle.textContent \= 'CIS Benchmark compliant. TLS enforced, zero public exposure, and least-privilege scoping.';  
    } else if (audit.grade \=== 'B') {  
      scoreHeadline.textContent \= 'Standard Compliant • Minor Hardening';  
      scoreHeadline.style.color \= '\#06b6d4';  
      scoreSubtitle.textContent \= 'Access is guarded. Consider explicit KMS upload mandates or VPC boundary conditions.';  
    } else if (audit.grade \=== 'C') {  
      scoreHeadline.textContent \= 'Suboptimal Security Posture';  
      scoreHeadline.style.color \= '\#f59e0b';  
      scoreSubtitle.textContent \= 'Missing encryption enforcement or overly broad wildcard action allowances.';  
    } else {  
      scoreHeadline.textContent \= 'Critical Vulnerability • Fatal Risk';  
      scoreHeadline.style.color \= '\#ef4444';  
      scoreSubtitle.textContent \= 'Public read/write access or missing TLS enforcement\! Immediate data exfiltration hazard.';  
    }

    checklistContainer.innerHTML \= '';  
    audit.results.forEach(item \=\> {  
      const el \= document.createElement('div');  
      el.className \= 'check-item';

      const icon \= item.status \=== 'PASS' ? '✅' : (item.status \=== 'WARN' ? '⚠️' : '❌');  
      const ptsClass \= item.status.toLowerCase();

      el.innerHTML \= \`  
        \<div class="check-icon"\>\${icon}\</div\>  
        \<div class="check-content"\>  
          \<div class="check-title-row"\>  
            \<span class="check-title"\>\${item.title}\</span\>  
            \<span class="check-pts \${ptsClass}"\>\${item.score}/\${item.maxScore} pts\</span\>  
          \</div\>  
          \<div class="check-desc"\>\${item.details}\</div\>  
        \</div\>  
      \`;  
      checklistContainer.appendChild(el);  
    });  
  }

  function renderSynthesizer() {  
    synthesizerOutput.textContent \= synthesizer.synthesize(currentPolicy, currentBucketName, activeTab);  
  }

  // Event Listeners  
  presetSelect.addEventListener('change', (e) \=\> {  
    loadPreset(e.target.value);  
  });

  bucketNameInput.addEventListener('input', (e) \=\> {  
    const oldName \= currentBucketName;  
    currentBucketName \= e.target.value.trim() || 'my-bucket';  
    // Update resources in statements  
    const jsonStr \= JSON.stringify(currentPolicy);  
    const updated \= jsonStr.split(\`arn:aws:s3:::\${oldName}\`).join(\`arn:aws:s3:::\${currentBucketName}\`);  
    currentPolicy \= JSON.parse(updated);  
    recalculateAndRender();  
  });

  toggleTls.addEventListener('change', () \=\> {  
    if (toggleTls.checked) {  
      if (\!currentPolicy.Statement.some(s \=\> s.Sid \=== 'EnforceTLSRequestsOnly')) {  
        currentPolicy.Statement.unshift(engine.createEnforceTLSDenyStatement(currentBucketName));  
      }  
    } else {  
      currentPolicy.Statement \= currentPolicy.Statement.filter(s \=\> s.Sid \!== 'EnforceTLSRequestsOnly');  
    }  
    recalculateAndRender();  
  });

  toggleKms.addEventListener('change', () \=\> {  
    if (toggleKms.checked) {  
      if (\!currentPolicy.Statement.some(s \=\> s.Sid \=== 'DenyUnencryptedObjectUploads')) {  
        currentPolicy.Statement.push(engine.createRequireKMSPutStatement(currentBucketName));  
      }  
    } else {  
      currentPolicy.Statement \= currentPolicy.Statement.filter(s \=\> s.Sid \!== 'DenyUnencryptedObjectUploads');  
    }  
    recalculateAndRender();  
  });

  toggleVpce.addEventListener('change', () \=\> {  
    if (toggleVpce.checked) {  
      if (\!currentPolicy.Statement.some(s \=\> s.Sid \=== 'RestrictAccessToVPCEndpoint')) {  
        currentPolicy.Statement.push(engine.createRestrictToVpcEndpointStatement(currentBucketName, vpceInput.value.trim() || 'vpce-0123456789abcdef0'));  
      }  
    } else {  
      currentPolicy.Statement \= currentPolicy.Statement.filter(s \=\> s.Sid \!== 'RestrictAccessToVPCEndpoint');  
    }  
    recalculateAndRender();  
  });

  toggleOac.addEventListener('change', () \=\> {  
    if (toggleOac.checked) {  
      if (\!currentPolicy.Statement.some(s \=\> s.Sid \=== 'AllowCloudFrontServicePrincipalReadOnly')) {  
        currentPolicy.Statement.push(engine.createCloudFrontOACStatement(currentBucketName, oacArnInput.value.trim()));  
      }  
    } else {  
      currentPolicy.Statement \= currentPolicy.Statement.filter(s \=\> s.Sid \!== 'AllowCloudFrontServicePrincipalReadOnly');  
    }  
    recalculateAndRender();  
  });

  btnExportJSON.addEventListener('click', () \=\> {  
    const dataStr \= "data:text/json;charset=utf-8," \+ encodeURIComponent(JSON.stringify(currentPolicy, null, 2));  
    const downloadAnchor \= document.createElement('a');  
    downloadAnchor.setAttribute("href", dataStr);  
    downloadAnchor.setAttribute("download", \`\${currentBucketName}-policy.json\`);  
    document.body.appendChild(downloadAnchor);  
    downloadAnchor.click();  
    downloadAnchor.remove();  
  });

  btnCopyConfig.addEventListener('click', () \=\> {  
    navigator.clipboard.writeText(synthesizerOutput.textContent).then(() \=\> {  
      showToast('Policy configuration copied to clipboard\!');  
    });  
  });

  tabButtons.forEach(btn \=\> {  
    btn.addEventListener('click', () \=\> {  
      tabButtons.forEach(b \=\> b.classList.remove('active'));  
      btn.classList.add('active');  
      activeTab \= btn.getAttribute('data-tab');  
      renderSynthesizer();  
    });  
  });

  function showToast(msg) {  
    const toast \= document.createElement('div');  
    toast.textContent \= msg;  
    toast.style.position \= 'fixed';  
    toast.style.bottom \= '24px';  
    toast.style.right \= '24px';  
    toast.style.background \= '\#06b6d4';  
    toast.style.color \= '\#04101e';  
    toast.style.padding \= '10px 18px';  
    toast.style.borderRadius \= '6px';  
    toast.style.fontWeight \= '700';  
    toast.style.fontSize \= '12px';  
    toast.style.zIndex \= '9999';  
    toast.style.boxShadow \= '0 4px 12px rgba(0,0,0,0.5)';  
    document.body.appendChild(toast);  
    setTimeout(() \=\> toast.remove(), 2500);  
  }

  // Initial Load  
  loadPreset('enterprise-datalake');  
});  
