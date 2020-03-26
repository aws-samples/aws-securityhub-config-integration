"""Script to integrate Config with Security Hub."""
import boto3

SECURITYHUB = boto3.client('securityhub')
CONFIG = boto3.client('config')


def get_description_of_rule(config_rule_name):
    """Gather description of config rule."""
    description = ""
    try:
        response = CONFIG.describe_config_rules(
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
    """Return compliance status."""
    status = ['FAILED', 3.0, 30]
    if new_status == 'COMPLIANT':
        status = ['PASSED', 0, 0]
    return status


def map_config_findings_to_sh(event, old_recorded_time):
    """Create custom finding."""
    new_findings = []
    new_status = event['detail']['newEvaluationResult']['complianceType']
    config_rule_name = event['detail']['configRuleName']
    compliance_status = get_compliance_and_severity(new_status)
    description = get_description_of_rule(config_rule_name)
    remediation_url = (f"https://console.aws.amazon.com/config/home?region=
                      {event['detail']['awsRegion']}#/rules/rule-details/
                      {config_rule_name}")
    new_findings.append({
        "SchemaVersion": "2018-10-08",
        "Id": event['id'],
        "ProductArn": (f"arn:aws:securityhub:{event['detail']['awsRegion']}:"
                       f"{event['detail']['awsAccountId']}:"
                       f"product/{event['detail']['awsAccountId']}/default"),
        "GeneratorId": event['detail']['configRuleARN'],
        "AwsAccountId": event['detail']['awsAccountId'],
        "Types": [
            "Software and Configuration Checks/AWS Config Analysis"
        ],
        "CreatedAt": old_recorded_time,
        "UpdatedAt": (event['detail']
                      ['newEvaluationResult']['resultRecordedTime']),
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
                'Id': event['detail']['resourceId'],
                'Type': event['detail']['resourceType'].split(":")[-1],
                'Partition': "aws",
                'Region': event['detail']['awsRegion']
            }
        ],
        'Compliance': {'Status': compliance_status[0]}
    })
    
    if new_findings:
        try:
            response = SECURITYHUB.batch_import_findings(Findings=new_findings)
            if response['FailedCount'] > 0:
                print(
                    "Failed to import {} findings".format(
                        response['FailedCount']))
        except Exception as error:
            print("Error: ", error)
            raise


def parse_message(event):
    """Initialize event logic."""
    details = event['detail']
    if (details['messageType'] == 'ComplianceChangeNotification' and
            "securityhub.amazonaws.com" not in details['configRuleARN']):
        if 'oldEvaluationResult' not in event['detail']:
            old_recorded_time = (event['detail']
                                 ['newEvaluationResult']['resultRecordedTime'])
        else:
            old_recorded_time = (event['detail']
                                 ['oldEvaluationResult']['resultRecordedTime'])
        map_config_findings_to_sh(event, old_recorded_time)
    else:
        print("Other Notification")


def lambda_handler(event, context):
    """Begin Lambda execution."""
    print("Event Before Parsing: ", event)
    print(lambda_context)
    parse_message(event)
