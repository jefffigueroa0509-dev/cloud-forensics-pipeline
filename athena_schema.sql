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