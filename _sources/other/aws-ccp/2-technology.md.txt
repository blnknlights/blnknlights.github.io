# Technologies

## Compute
### EC2
```
- AMI - Amazon Machine Image - This is a template for the OS to install on an EC2
- 750 compute hours on the "Free Tier" plan

```
```
- can be accessed over: 
    - management console         - Through a webshell
    - ssh                        - With ssh keys 
    - EC2 Instance Connect (EIC) - Uses IAM policies to control ssh access
    - AWS Systems Manager        - Through a webshell
```
```
- pricing options: 
    - On-Demand                  - Fixed price based on instance type, no contract, you pay only for what you use
    - Spot                       - Your request will only be fulfilled if capacity is available, cheap, usefull if we don't care when you jobs run
    - Reserved  Instances        - Commit for 1 or 3 year term
    - Dedicated Hosts            - Pay for a dedicated physical server, e.g. not shared with other apps and users
    - Savings Plans              - Commit to compute usage (measured per hours) for 1 or 3 years
```
```
- EC2 Elastic Load Balancing     - Distributes your incoming app traffic across multiple EC2
                                 - Classic load balancers
                                 - Application load balancers
                                 - Gateway load balancers
                                 - Network load balancers
```
```
- EC2 - Auto Scaling             - Adds or replaces EC2 instances automatically across AZs, based on need and changing demand 
                                 - Horizontal scaling  (add servers)
                                 - Scaling out         (remove servers)
```
### Lambda
```
- Lambda is a serverless compute service that lets you run code without managing servers
- in the lambda vernacular app code is called functions 
- scales automatically
- lambda functions have a 15 min timeout.
- supports - java, go, powershell, node.js, C#, python, ruby
```
```
- pricing model
    - you are charged based on the duration and number of requests
    - 1 Compute Time
    - 2 Request count
    - 3 Always free - 1 million requests for free each month even after the free tier is expired
```

> node.js code to try as a lambda function
```javascript
const https = require('https')
let url = "https://www.amazon.com"

exports.handler = function(event, context, callback) {
    https.get(url, (res) => {
        callback(null, res.statusCode)
    }).on('error', (e) => {
        callback(Error(e))
    })
}
```

> python code to try as a lambda function
```python
import json

def lambda_handler(event, context):
    message = 'Hello {} {}! Keep being awesome!'.format(event['first_name'], event['last_name'])  

    #print to CloudWatch logs
    print(message)

    return { 
    'message' : message
    }  
```
### Fargate
```
- Serverless compute engine for containers
- Scales automatically
```

### Lightsail
```
- Allows to quickly launch all the resources you need for small projects
- Deploy preconfigured apps like WordPress at the click of a button
- Simple screens for beginners
- Low predictable monthly fee as low as 3.50$
- Includes: 
    - a VM 
    - SSD based storage 
    - data transfer 
    - DNS management 
    - static IP
```

### AWS Outpost
```
- Supports workloads that need to remain on-premises
- AWS delivers and installs servers in your datacenter 
- Used for a hybrid experience
- give access to the cloud services and APIs of AWS on premises
```

### AWS Batch
```
- Allows you to process large workloads in smaller chunks (or batches)
- runs hundreds of smaller batch processing jobs 
- Dynamically provisions instances based on volume
```



## Storage
### S3
```
- Access can be secured by ACLs, Bucket policies, access point policies or all 3
- Versionning can be enabled 
- S3 access logs 
- S3 is a regional service but bucket names must be globally unique
```
```
- 1. S3 Standard                         - For frequently accessed data
- 2. S3 Intelligent-Tiering              - For unknown or changing access pattern
- 3. S3 Standard-Infrequent Access (IA)  - Infrequent access 
- 4. S3 One Zone-Infrequent Access (IA)  - Infrequent access one zone
- 5. S3 Glacier                          - Long term backup - cheap - slow access times (minutes to hours)
- 6. S3 Glacier Deep Dive                - Long term backup - cheaper - slower access times (hours to days)
- 7. S3 Outposts                         - On prem
```
```
- Use cases:
    - Static Websites 
    - Data archive 
    - Mobile apps 
    - Anaylytics systems
```

### EBS - Elastic Block Store
```
- You can think about it like a flash drive or a virtual disk
- Data persists when the instance is not running 
- Tied to one AZ
- Can only be attached to one instance in the same AZ
```

### EFS - Elastic File System
```
- serverless network file system for sharing files
- only supports linux 
- more expensive than EBS 
- Accessible across multiple AZ in the same region
- Recommended for main app dir
- Recommended for Lift-and-shift enterprise apps
```

### EC2 Instance Store
```
- storage on a disk physically attached to the instance
- very fast i/o
- does not persist after the instance is stopped or reboot 
- only good for temporary storage 
```

### Storage Gateway
```
- hybrid data storage service 
- Connect on-premises and cloud data 
- Recommended to - Move backups to the cloud
- Recommended for - Reducing costs for hybrid cloud 
- Recommended for - Low latency access to data
```

### AWS Backup
```
- helps manage data backups across multiple AWS Services
- integrates with EC2, EBS, EFS and more 
- create a backup plan that includes frequency and retention
```



## Edge Networking  
### Cloudfront
```
- Makes content available globally or restricts it based on location
- Speeds up delivery of  static and dynamic web content
- Uses edge locations to cachecontent
- CloudFront is often used with S3 to deploy content globally.
- CloudFront can stop certain web attacks, like DDoS. We'll talk more about DDoS in the security lesson.
- Geo-restriction prevents users in certain countries from accessing content.
```

### Global Accelerator
```
- Improves latency and availability of single-Region applications
- Sends traffic through the AWS global network infrastructure
- 60% performance boost
- Automatically re-routes traffic to healthy available regional endpoints
```

### S3 Transfer Acceleration
```
- improves content uploads and downloads to and from S3 buckets
- Fast transfer of files over long distances
- Uses CloudFront’s globally distributed edge locations
- Customers around the world can upload to a central bucket
```



## Networking
### VPC - Virtual Private Cloud
```
- Private virtual network 
- launch resources like EC2 inside a VPC
- VPCs can span accross multiple AZ
- inside VPC your can setup Private Subnets & Public Subnets
- NACL - Network Access Control List - ensure proper traffic is allowed into the subnet 
- Router / Route Table 
- Internet gateway 
- VPC Peering Connections - allow to connect 2 VPCs
```

### Route 53
```
- Essentially AWS DNS service
- Performs health cheks on AWS resources 
- Supports hybrid cloud architectures 
```

### Direct Connect
```
- Dedicated physical network connection from on-prem to an AWS DC
- Data travels over a private network
- Suports hybrid cloud architecturs
```

### AWS VPN
```
- Similar to Direct Connect but data travels over the public internet
- Virtual Private Gateway supports the VPN tunel on AWS side
- Customer Gateway supports the VPN tunel on the customer's DC side
```

### API Gateway
```
- integrates with services like AWS Lambda
```



## Databases
### RDS - Relational Database Service
```
- Relational Database
- Supported DB engines: 
    - Amazon Aurora
    - PostgreSQL
    - MySQL
    - MariaDB
    - Oracle
    - Microsoft SQL Server
- HA and fault tolerance using multi AZ Deployment options
- Serverless - Auto DB patching, os patching, backups and more 
- read replicas accross regions for improved performance and durability
```

### Aurora
- Relational Database
```
- supports MySQL and PostgreSQL database engines 
- 5x faster than MySQL 
- Auto Scaling 
- Managed by RDS
```

### DynamoDB
```
- NoSQL - key-value pair db
- Serverless
- Non relational
- Auto Scaling 
```

### DocumentDB
```
- Document DB
- MongoDB compatible
- Serverless
- Non relational
```

### ElastiCache
```
- In-Memory datastore
- Compatible with Redis and Memcached 
- Data can be lost as this is in memory
- low latency
```

### Neptune
```
- Graph DB
- Support highly connected datasets like social media networks
- Serverless
- Fast and reliable
```

## Migration and transfer
### DMS - Database Migration Service
```
- Migrate on-premises databases to AWS
- Continuous data replication
- Supports homogeneous and heterogeneous migrations
- Virtually no downtime
```

### SMS Server Migration Service
```
- Migrates on-premises servers to AWS
- Server saved as a new Amazon Machine Image (AMI)
- Use AMI to launch servers as EC2 instances
```

### Snow Family
```
- Snow Cone      - 8 terabytes physical device
- Snow Ball      - Petabyte-scale data transport solution
- Snow Ball Edge - Petabyte-scale data transport solution - supports EC2 and Lambda
- Snowmobile     - Multi-petabyte or exabyte scale - Securely transported
```

### DataSync
```
- DataSync allows for online data transfer from on-premises to AWS storage services like S3 or EFS
- Migrates data from on-premises to AWS
- Copy data over Direct Connect or the internet
- Replicate data 
- cross-Region or cross-account
- Copy data between AWS storage services
```



## Analytics
### Redshift
```
- Data warehousing solution
- Improves speed and efficiency
- Handles exabyte-scale data
```

### Athena
```
- Query service for S3
- Analyze S3 data using SQL
- Pay per query
- Considered serverless
```

### Glue
```
- Extract, transform, load (ETL) service
- Glue prepares your data for analytics.
```

### Kinesis
```
- Kinesis allows you to analyze data and video streams in real time
- Analyze real-time, streaming data
- Supports video, audio, application logs, website clickstreams, and IoT
```

### EMR - Elastic MapReduce
```
- helps you process large amounts of data
- Analyze data using Hadoop
- Works with big data frameworks
```

### Data Pipeline
```
- Data Pipeline helps you move data between compute and storage services running either on AWS or on-premises
- Moves data at specific intervals
- Sends notifications on success or failure
- Moves data based on conditions
```

### QuickSight
```
- helps you visualize your data
- Build interactive dashboards
- Embed dashboards in your applications
```

## Machine Learning
### Rekognition
```
- image recognition
- facial analysis
- text recognition
```

### Comprehend
```
- NLP - Natural Language Processing service
- finds insights and relationships in text 
```

### Polly
```
- turns text into speach
```

### SageMaker
```
- Flagship machine learning service on AWS
- Prepare data for models 
- Train and deploy models 
- provide deep learning AMIs
```

### Translate 
```
- provides real time and batch language translation
```

### Lex
```
- helps you build chatbots
- this is what powers Alexa
```



## Developer Tools 
### Cloud9
```
- IDE in the web browser
```
### CodeCommit
```
- Source control system for private it repos
```
### Code Deploy
```
- build and test framework
```
### Code Pipeline
```
- allows you to implement a CI/CD pipeline
```
### X-Ray
```
- Helps you debug production apps 
```
### CodeStar
```
- Helps devs collaboratively work on development projects
- Track bugs and issues
```



## Deployment & Infrastructure Management
### CloudFormation
```
- IaC - Infrastructure as Code service 
- allows to provision AWS resources using yaml or json definitions
```
### Elastic Beanstalk
```
- deploy your web apps & services to AWS
- cannot be used to deploy on prem
```
### Ops Works
```
- allows to use Chef or Puppet to automate the configuration of your servers 
- deploy code on prem
```



## Messaging & Integration
### SQS - Simple Queue Service
```
- message queues support loose coupling
- messages in queues are processed in FIFO order
- Messages are processed in an asynchronous manner
- Allows component-to-component communication using messages 
- Multiple components (or producers) can add messages to the queue
```

### SNS - Simple Notification Service
```
- Allows to send raw formated email 
- Allows to send text messages  
- Subscribers receive messages
- Publish messages to a topic
```

### SES - Simple Email Service
```
- Allows to send rich format emails like HTML
- Ideal for things like marketing campaigns
```



## Auditing, Monitoring & Logging
### Cloudwatch
```
- A collection of services 
- CloudWatch Alarms
- CloudWatch Logs
- CloudWatch Metrics
- CloudWatch Events
```

### Cloudtrail
```
- Log and retain account activity 
- Track activity through the console, SDKs, and CLI
- Identify which user made changes
- Detect unusual activity in your account
```



## Additional Services
### Amazon Workspaces
```
- Provides virtualized desktops 
- Linux or Windows
```

### Amazon Connect
```
- Contact center service 
- Provides customer service functionality
```
