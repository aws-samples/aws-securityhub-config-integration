"""Script to integrate Config with Security Hub."""
import logging
import boto3
import hashlib
import time

logger = logging.getLogger()
logger.setLevel(logging.INFO)

SECURITYHUB = boto3.client('securityhub')
CONFIG = boto3.client('config')
MAX_RETRIES = 3


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
        logger.error(f"Exception: {error}")
        raise


def get_compliance_and_severity(new_status):
    """Return compliance status."""
    status = ['FAILED', 3.0, 30]
    if new_status == 'COMPLIANT':
        status = ['PASSED', 0, 0]
    elif new_status == 'NOT_APPLICABLE':
        # we set it to PASSED as opposed to NOT_AVAILABLE. Setting to NOT_AVAILABLE triggers a
        # transition of the WorkflowStatus to NEW. Something we do not want since NOT_APPLICABLE
        # in AWS Config means the resource has been deleted
        # see https://docs.aws.amazon.com/config/latest/APIReference/API_DescribeComplianceByResource.html.
        status = ['PASSED', 0, 0]
    return status

def get_workflow_status(compliance_status):
    if compliance_status == 'PASSED' or compliance_status == 'NOT_AVAILABLE':
        updated_status = 'RESOLVED'
    else:
        updated_status = 'NEW'
    return updated_status


def batch_import_findings(new_findings):
    try:
        response = SECURITYHUB.batch_import_findings(Findings=new_findings)
        if response['FailedCount'] > 0:
            logger.info(f"Failed to import {response['FailedCount']} findings")
        return response
    except Exception as error:
        logger.error(f"Exception: {error} ")
        raise


def batch_update_findings(finding_id, updated_status, event_details):
    try:
        for i in range(MAX_RETRIES):

            response = SECURITYHUB.batch_update_findings(
                FindingIdentifiers=[
                    {
                        'Id': finding_id,
                        'ProductArn': (f"arn:aws:securityhub:{event_details['awsRegion']}:"
                                    f"{event_details['awsAccountId']}:"
                                    f"product/{event_details['awsAccountId']}/default")
                    },
                ],
                Workflow={
                    'Status': updated_status
                },
            )

            #Retry if UnprocessedFindings exist
            if response['UnprocessedFindings']:
                logger.error(f"Failed to update (try number='{i}'/{MAX_RETRIES-1}) finding worflow status: '{response}'" )
                time.sleep(1)
            else:
                logger.info(f"BatchUpdateFindings id='{finding_id}' workflow_status='{updated_status}' response='{response}'")
                break

        return response
    except Exception as error:
        logger.error(f"Exception: {error}")
        raise


def map_config_findings_to_sh(event, old_recorded_time):
    """Create custom finding."""
    new_findings = []
    event_details = event['detail']
    new_status = event_details['newEvaluationResult']['complianceType']
    config_rule_name = event_details['configRuleName']
    compliance_status = get_compliance_and_severity(new_status)
    description = get_description_of_rule(config_rule_name)
    remediation_url = (f"https://console.aws.amazon.com/config/home?region={event_details['awsRegion']}#/rules/details?configRuleName={config_rule_name}")
    finding_hash = hashlib.sha256(f"{event_details['configRuleARN']}-{event_details['resourceId']}".encode()).hexdigest()
    finding_id = (f"arn:aws:securityhub:{event_details['awsRegion']}:{event_details['awsAccountId']}:config/rules/{config_rule_name}/finding/{finding_hash}")
    updated_status = get_workflow_status(compliance_status[0])

    new_findings.append({
        "SchemaVersion": "2018-10-08",
        "Id": finding_id,
        "ProductArn": (f"arn:aws:securityhub:{event_details['awsRegion']}:"
                    f"{event_details['awsAccountId']}:"
                    f"product/{event_details['awsAccountId']}/default"),
        "GeneratorId": event_details['configRuleARN'],
        "AwsAccountId": event_details['awsAccountId'],
        'ProductFields': {
            'ProviderName': 'AWS Config'
        },
        "Types": [
            "Software and Configuration Checks/AWS Config Analysis"
        ],
        "CreatedAt": old_recorded_time,
        "UpdatedAt": (event_details['newEvaluationResult']['resultRecordedTime']),
        "Severity": {
            "Product": compliance_status[1],
            "Normalized": compliance_status[2],
            "Label": "MEDIUM"
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
                'Id': event_details['resourceId'],
                'Type': event_details['resourceType'],
                'Partition': "aws",
                'Region': event_details['awsRegion']
            }
        ],
        'Compliance': {'Status': compliance_status[0]},
        'Workflow': {'Status': updated_status}
    })

    if new_findings:
        #batch_import_findings allows to set ComplianceStatus
        response = batch_import_findings(new_findings)
        logger.info(f"BatchImportFindings id='{finding_id}' compliance_status='{compliance_status[0]}' configRuleComplianceType='{new_status}' workflow_status='{updated_status}' description='{description}'")

        if 'oldEvaluationResult' in event_details:
            #batch_update_findings allows to set WorkflowStatus
            response = batch_update_findings(finding_id, updated_status, event_details)


def parse_message(event):
    """Initialize event logic."""
    event_details = event['detail']
    if (event_details['messageType'] == 'ComplianceChangeNotification'):
        if 'oldEvaluationResult' not in event_details:
            old_recorded_time = (event_details['newEvaluationResult']['resultRecordedTime'])
        else:
            old_recorded_time = (event_details['oldEvaluationResult']['resultRecordedTime'])
        map_config_findings_to_sh(event, old_recorded_time)
    else:
        logger.info("Other Notification")


def lambda_handler(event, context):
    """Begin Lambda execution."""
    logger.info(f"Event Before Parsing: {event}")
    parse_message(event)