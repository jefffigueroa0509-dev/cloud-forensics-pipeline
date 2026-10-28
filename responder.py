import boto3
import time

# Initialize Athena and IAM clients
ATHENA_CLIENT = boto3.client('athena', region_name='us-east-2')
IAM_CLIENT = boto3.client('iam')

DATABASE = 'default'
OUTPUT_LOCATION = 's3://my-cloudtrail-forensic-logs-jf/athena-results/'

def run_athena_query(query):
    print("[*] Submitting Athena query...")
    response = ATHENA_CLIENT.start_query_execution(
        QueryString=query,
        QueryExecutionContext={'Database': DATABASE},
        ResultConfiguration={'OutputLocation': OUTPUT_LOCATION}
    )
    query_execution_id = response['QueryExecutionId']
    
    # Poll until query completes
    while True:
        status_response = ATHENA_CLIENT.get_query_execution(QueryExecutionId=query_execution_id)
        status = status_response['QueryExecution']['Status']
        state = status['State']
        
        if state == 'SUCCEEDED':
            break
        elif state in ['FAILED', 'CANCELLED']:
            reason = status.get('StateChangeReason', 'Unknown reason')
            raise Exception(f"Athena query failed: {state}. Reason: {reason}")
        time.sleep(2)
        
    # Fetch results
    results_response = ATHENA_CLIENT.get_query_results(QueryExecutionId=query_execution_id)
    return results_response['ResultSet']['Rows']

def detect_and_contain():
    print("[*] Scanning CloudTrail logs via Athena for unauthorized policy attachments...")
    
    # Query targeting IAM policy attachments across multi-region logs
    query = """
        SELECT 
            useridentity.username,
            sourceipaddress,
            eventname,
            eventtime,
            useridentity.accesskeyid
        FROM default.cloudtrail_logs
        WHERE eventname = 'AttachUserPolicy'
        ORDER BY eventtime DESC
        LIMIT 5;
    """
    
    rows = run_athena_query(query)
    
    # Check if any rows returned (skipping the header row at index 0)
    if len(rows) <= 1:
        print("[-] No unauthorized privilege escalations detected.")
        return

    for row in rows[1:]: # Skip header
        cols = row['Data']
        username = cols[0].get('VarCharValue', 'Unknown')
        source_ip = cols[1].get('VarCharValue', 'Unknown')
        event_name = cols[2].get('VarCharValue', 'Unknown')
        event_time = cols[3].get('VarCharValue', 'Unknown')
        access_key_id = cols[4].get('VarCharValue', 'None')
        
        print(f"[!] ALERT: Detected {event_name} by user '{username}' using Key {access_key_id} from IP {source_ip} at {event_time}!")
        
        # Containment Logic: Deactivate compromised access key if present
        if access_key_id and access_key_id != 'None' and username != 'Unknown':
            print(f"[*] Containment Action: Deactivating access key {access_key_id} for user {username}...")
            try:
                IAM_CLIENT.update_access_key(
                    UserName=username,
                    AccessKeyId=access_key_id,
                    Status='Inactive'
                )
                print(f"[+] SUCCESS: Access key {access_key_id} has been deactivated.")
            except Exception as e:
                print(f"[-] FAILED to deactivate access key: {e}")

if __name__ == "__main__":
    detect_and_contain()