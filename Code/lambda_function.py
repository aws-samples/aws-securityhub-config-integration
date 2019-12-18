import boto3

config = boto3.client('config')
securityhub = boto3.client('securityhub')

def get_description_of_rule(config_rule_name):
    # This function returns the description of a config rule
    description = ""
    try:
        response = config.describe_config_rules(
            ConfigRuleNames=[config_rule_name]
        )
        if 'Description' in response['ConfigRules'][0]:
            description = response['ConfigRules'][0]['Description']
        else:
            description = response['ConfigRules'][0]['ConfigRuleName']
        return description
    except Exception as error:
        print("Error: ", error)
        raise
        
def get_compliance_and_severity(new_status):
    # This function returns the compliance status and severity of the finding 
    status = ['FAILED', 3.0, 30]
    if new_status == 'COMPLIANT':
        status = ['PASSED', 0, 0]
    return status

def map_config_findings_to_sh(args):
    # This function import findings from aws-config to securityhub  
    new_findings = []
    finding_id = args[0]
    account_id = args[1]
    config_rule_name = args[2]
    resource_type = args[3]
    resource_id = args[4]
    region = args[5]
    new_status = args[6]
    new_recorded_time = args[7]
    old_recorded_time = args[8]
    config_rule_arn = args[9]
    compliance_status = get_compliance_and_severity(new_status)
    description = get_description_of_rule(config_rule_name)
    remediation_url = "https://console.aws.amazon.com/config/home?region="+region+"#/rules/rule-details/"+config_rule_name
    new_findings.append({
        "SchemaVersion": "2018-10-08",
        "Id": finding_id,
        "ProductArn": "arn:aws:securityhub:{0}:{1}:product/{1}/default".format(region, account_id),
        "GeneratorId": config_rule_arn,
        "AwsAccountId": account_id,
        "Types": [
            "Software and Configuration Checks/AWS Config Analysis"
        ],
        "CreatedAt": old_recorded_time,
        "UpdatedAt": new_recorded_time,
        "Severity": {
            "Product": compliance_status[1],
            "Normalized": compliance_status[2]
        },
        "Title": config_rule_name,
        "Description": description,
        'Remediation': {
            'Recommendation': {
                'Text': 'For directions on how to fix this issue, see the remediation action on the rule details page in AWS Config console',
                'Url': remediation_url
            }
        },
        'Resources': [
            {
                'Id': resource_id,
                'Type': resource_type,
                'Partition': "aws",
                'Region': region
            }
        ],
        'Compliance': {'Status': compliance_status[0]}
    })
    
    if new_findings:
        try:
            response = securityhub.batch_import_findings(Findings=new_findings)
            if response['FailedCount'] > 0:
                print("Failed to import {} findings".format(response['FailedCount']))
        except Exception as error:
            print("Error: ", error)
            raise
                    
def parse_message(event):
    # This function parse the cloudwatch event to get required data for the ingestion of finding in security hub
    finding_id = event['id']
    if event['detail']['messageType'] == 'ComplianceChangeNotification' and "securityhub.amazonaws.com" not in event['detail']['configRuleARN']:
        account_id = event['detail']['awsAccountId']
        config_rule_name = event['detail']['configRuleName']
        config_rule_arn = event['detail']['configRuleARN']
        resource_type = event['detail']['resourceType']
        resource_id = event['detail']['resourceId']
        region = event['detail']['awsRegion']
        new_status = event['detail']['newEvaluationResult']['complianceType']
        new_recorded_time = event['detail']['newEvaluationResult']['resultRecordedTime']
        if 'oldEvaluationResult' not in event['detail']:
            old_recorded_time = event['detail']['newEvaluationResult']['resultRecordedTime']
        else:
            old_recorded_time = event['detail']['oldEvaluationResult']['resultRecordedTime']   
        print("Compliance change notification for config rule: ", config_rule_name)    
        args = [finding_id, account_id, config_rule_name, resource_type, resource_id, region, new_status, new_recorded_time, old_recorded_time, config_rule_arn]
        map_config_findings_to_sh(args)
    else:  
        print("Other Notification")

def lambda_handler(event, context):
    print("Event Before Parsing: ", event)
    parse_message(event)