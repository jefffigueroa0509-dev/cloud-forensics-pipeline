Markdown
# Cloud-Native Automated Threat Detection & Containment Pipeline

## Executive Summary
This project implements an automated, cloud-native incident response pipeline designed to detect unauthorized identity and access management (IAM) privilege escalations across multi-region AWS environments. Utilizing **Python (`boto3`)**, **Amazon Athena**, and **AWS CloudTrail**, the automated engine continuously queries telemetry across global and regional services to identify malicious actions—specifically unauthorized `AttachUserPolicy` executions—and immediately triggers programmatic remediation to deactivate compromised access keys.

---

## Technical Architecture & Workflow

[ AWS CloudTrail ] (Multi-Region Logging)
│
▼
[ Amazon S3 Bucket ] (Log Repository)
│
▼
[ Amazon Athena ] (Partition Projection Query Engine)
│
▼
[ Python Script (responder.py) ] ──(boto3 API)──► [ IAM Access Key Deactivation ]

**Log Ingestion & Aggregation:** 
   AWS CloudTrail captures API activity across multi-region infrastructure. Global service events (such as IAM identity modifications) land in `us-east-1`, while regional resource activity is logged in `us-east-2`.
2. **Multi-Region Telemetry Querying:** 
   Amazon Athena, configured with dynamic **Partition Projection**, scans structured JSON logs across regional S3 partitions without requiring manual partition maintenance or incurring full-bucket scan overhead.
3. **Automated Incident Response & Containment:** 
   The Python detection engine (`responder.py`) parses Athena query results, extracts adversary metadata (Username, Access Key ID, Source IP, Timestamp), and invokes the `iam:UpdateAccessKey` API to set compromised credentials to `Inactive`.

---

## Key Features & Analytical Capabilities

* **Multi-Region Global Event Correlation:** Solves the common log-visibility blind spot by configuring Athena partition projection over both global (`us-east-1`) and regional (`us-east-2`) S3 folder paths.
* **Schema-Aware Log Parsing:** Leverages Hive `JsonSerDe` and `CloudTrailInputFormat` to query nested CloudTrail JSON structures directly.
* **Rapid Dwell Time Reduction:** Automates containment workflows to programmatically revoke access keys within seconds of event ingestion, neutralizing unauthorized administrative access.
* **Detailed Audit & Reporting:** Outputs structured log alerts capturing key Indicators of Compromise (IOCs) including source IP address, principal identity, and precise timestamp.

---

## Repository Structure

```text
├── responder.py          # Python detection engine & boto3 remediation script
├── athena_schema.sql     # DDL script creating partition-projected CloudTrail table
└── README.md             # Project documentation and operational guide

Deployment & Setup Guide
1. Prerequisites
AWS CLI installed and configured with appropriate IAM permissions.

AWS CloudTrail enabled and delivering logs to an Amazon S3 bucket.

Python 3.x installed with boto3.

2. Configure Athena Table Schema
Execute the DDL script in athena_schema.sql within the Amazon Athena Query Editor (replace <YOUR-ACCOUNT-ID> and bucket names accordingly):
CREATE EXTERNAL TABLE default.cloudtrail_logs (
  version string,
  useridentity struct<
    type: string,
    principalid: string,
    arn: string,
    accountid: string,
    invokedby: string,
    accesskeyid: string,
    username: string,
    sessioncontext: struct<
      attributes: struct<
        mfaauthenticated: string,
        creationdate: string>,
      sessionissuer: struct<
        type: string,
        principalid: string,
        arn: string,
        accountid: string,
        username: string>,
      ec2roledelivery: string,
      webidentitytokendetails: string>>,
  eventtime string,
  eventname string,
  awsregion string,
  sourceipaddress string,
  useragent string,
  errorcode string,
  errormessage string,
  requestparameters string,
  responseelements string,
  additionaleventdata string,
  requestid string,
  eventid string,
  readonly string,
  resources array<struct<
    arn: string,
    accountid: string,
    type: string,
    rnamen: string>>,
  eventtype string,
  apiversion string,
  recipientaccountid string,
  serviceeventdetails string,
  sharedeventid string,
  vpcendpointid string,
  tlsdetails struct<
    tlsversion: string,
    ciphersuite: string,
    clientprovidedhostheader: string>
)
PARTITIONED BY (
  region string,
  date string
)
ROW FORMAT SERDE 'org.apache.hive.hcatalog.data.JsonSerDe'
STORED AS INPUTFORMAT 'com.amazon.emr.cloudtrail.CloudTrailInputFormat'
OUTPUTFORMAT 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat'
LOCATION 's3://<BUCKET-NAME>/AWSLogs/<ACCOUNT-ID>/CloudTrail/'
TBLPROPERTIES (
  'projection.enabled' = 'true',
  'projection.region.type' = 'enum',
  'projection.region.values' = 'us-east-1,us-east-2',
  'projection.date.type' = 'date',
  'projection.date.range' = '2026/01/01,2030/12/31',
  'projection.date.format' = 'yyyy/MM/dd',
  'projection.date.interval' = '1',
  'projection.date.interval.unit' = 'DAYS',
  'storage.location.template' = 's3://<BUCKET-NAME>/AWSLogs/<ACCOUNT-ID>/CloudTrail/${region}/${date}'
);

3. Execution & Automated Containment
Run the detection script locally or as part of a scheduled cron job / Lambda execution:

Bash
python responder.py

Sample Output:
Plaintext
[*] Scanning CloudTrail logs via Athena for unauthorized policy attachments...
[*] Submitting Athena query...
[!] ALERT: Detected AttachUserPolicy by user 'dev-user-temp' using Key AKIAXXXXXXXXXXXXXXXX from IP 192.0.2.45 at 2026-10-28T14:19:34Z!
[*] Containment Action: Deactivating access key AKIAXXXXXXXXXXXXXXXX for user dev-user-temp...
[+] SUCCESS: Access key AKIAXXXXXXXXXXXXXXXX has been deactivated.
Security & Operational Considerations
Least Privilege Remediation: The response engine should run under an isolated IAM Role granted minimal permissions required for iam:UpdateAccessKey on targeted resources.

Log Ingestion Latency: CloudTrail log delivery typically operates on a 5-to-15 minute latency window. For sub-second response times, this architecture can be extended using AWS EventBridge rule patterns linked directly to SQS/Lambda.