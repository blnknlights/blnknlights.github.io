# Security and Compliance

## Shared responsibility model
```
- AWS is responsible for the security of the cloud 
- You are responsible for security in the cloud 
```



## Well architected framework

```
- 5 pillars:
    - Operational excellence
    - Security
    - Reliability
    - Performance Efficiency
    - Cost Optimization
```

### Operational excellence
```
- script operations as code
- plan for and anticipate failure
- deploy smaller reversible changes
- learn from failure and refine
```

### Security
```
- automate security tasks
- encrypt data in transit and at rest
- assign only the least priviledges required 
- track who did what and when
- ensure security at all application layers 
```

### Reliability
```
- recover from failure automatically
- reduce idle resources 
- scale horizontally for resilience 
- manage change through automation
- test recovery procedures 
```

### Performance Efficiency
```
- use serverless first
- delegate tasts to a cloud vendor
- use multi region deployements 
- experiment with virtual resources 
```

### Cost Optimization
```
- utilize consumption based pricing 
- implement cloud financial management 
- measure overall efficiency
- pay only for resources your application requires 
```



## Security
### IAM - Identity & Access Management
```
- Authentication -> Who
- Authorization  -> What
- Users are created in IAM to represent users or applications 
- new users have no access 
- you can leverage IAM to give them access to what they need based on the principle of least privilege
- access is assigned to users and groups using policy and roles 
- groups - place users in groups, give accesses to groups 
- roles - define access permissions and are temporarilly assumed to IAM users or services 
- policy - json - assign roles to users and groups 
- credential report - lists all the users in your account and the status of their various credentials
```

### WAF - Web Application Firewall
```
- protects against web attacks by matching patterns 
- protects against SQLi
- protects against XXS
- WAS can stand in front of CloudFront, or in front of an LB
```

### Shield
```
- protects against DDoS
- Shield standard is free - common and frequently occuring attacks 
- Shield advanced is a payed service - advanced protection and 24/7 access to AWS experts for a fee
```

### Macie
```
- helps you discover and protect sensitive data 
- machine learning based secret and PII scan for S3
```

### Config
```
- tracks configuration changes over time 
- delivers history configuration files to S3
```

### Guard Duty
```
- threat detection tool based on machine learning 
- annomaly detection over all API calls
```

### Inspector
```
- Agent installed on EC2 instances 
- reports vulns found and vulnerable software versions installed
- checks access from the internet, root logins and so on
```

### Artifact
```
- on demand access to AWS security and compliance reports 
- get reports for things like PCI, SOX, HIPAA, SOX, HIPAA, SOX, HIPAA, SOX, HIPAA, SOX, HIPAA, SOX, HIPAA, SOX, HIPAA, SOX, HIPAA, SOX, HIPAA and so on
```

### Cognito
```
- access control for web and mobile apps 
- assist with users sign up/sign in
- provides authentication and authorization 
```



## Encryption
### KMS - Key Management Service
```
- allows you to generate and store encryption keys 
- key generator 
- store and control keys
- AWS manages the encryption keys 
- automatically enabled for certain services
```

### Cloud HSM - Hardware Security Module
```
- dedicated hardware for encryption keys 
- generate and manage your own keys 
- AWS doesn't have access to your keys
```

### Secrets Manager
```
- Manage retrieve rotate secrets 
- you can encrypt secrets at rest
- integrates with RedShift, RDS and DocumentDB
```
