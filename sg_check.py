import boto3
import botocore
import json


### Constant value.
APPLICABLE_RESOURCES = ["AWS::EC2::SecurityGroup"]

SG_IP_RANGE_KEY = 'IpRanges'
SG_CIDRIP_KEY = 'CidrIp'

SG_GROUP_PAIR_KEY = 'UserIdGroupPairs'
SG_GROUP_ID_KEY = 'GroupId'

# parameter key
DEBUG = 'debug'  # Boolean type, True or False.
PERMIT_IP_RANGES = 'permit_ip_ranges'  # 10.0.0.0/24,10.0.1.0/25,...


# Already permitted security groupId list.
#  For avoiding loop check, in case cross reference security groupId.
g_checked_sg_ids = []

# Debug flag.
g_debug_enabled = False



class NotPermitException(Exception):
    """
    This exception class is Don't permit ip range of security group.
    """
    pass


def evaluate_compliance(configuration_item, permit_ip_ranges):
    """
    Evaluation compliance.
    If evaluation is correct return COMPLIANT, ohterwise return NON_COMPLIANT.
    """

    if configuration_item["resourceType"] not in APPLICABLE_RESOURCES:
        return {
            "compliance_type" : "NOT_APPLICABLE",
            "annotation" : "The rule doesn't apply to resources of type " +
            configuration_item["resourceType"] + "."
        }

    if configuration_item["configurationItemStatus"] == "ResourceDeleted":
        return {
            "compliance_type": "NOT_APPLICABLE",
            "annotation": "The configurationItem was deleted and therefore cannot be validated."
        }


    group_id = configuration_item["configuration"]["groupId"]

    print('Evaluate {} start'.format(group_id))

    if is_permit_sg(group_id, permit_ip_ranges):
        return {
            "compliance_type": "COMPLIANT",
            "annotation": 'SecurityGroup {} ingress is corrected.'.format(group_id)
        }
    else:
        return {
            "compliance_type" : "NON_COMPLIANT",
            "annotation": 'SecurityGroup {} ingress is corrected.'.format(group_id)
        }


def is_permit_sg(group_id, permit_ip_ranges):
    """
    To check whether all of security group row is permitted.
    For ingress ip_range, security group.
    """
    
    global g_debug_enabled
    global g_checked_sg_ids

    try:
        client = boto3.client("ec2");
        response = client.describe_security_groups(GroupIds=[group_id])

        # Register self group_id, for cross reference.
        g_checked_sg_ids.append(group_id)

    except botocore.exceptions.ClientError as e:
        return False
        

    if g_debug_enabled:
        print("security group definition: ", json.dumps(response, indent=2))


    # Check sourse of security group.
    for sg_row in response['SecurityGroups'][0]['IpPermissions']:

        if not is_permit_ip_ranges(sg_row, permit_ip_ranges):
            return False

        if not is_permit_sg_src(sg_row, permit_ip_ranges):
            return False


    return True


def is_permit_ip_ranges(sg_row, permit_ip_ranges):
    """
    To check whether all of security group row is permitted.
    For ingress ip_range.
    """

    print('is_permit_ip_ranges: {}'.format(sg_row[SG_IP_RANGE_KEY]))

    if not sg_row[SG_IP_RANGE_KEY]:
        return True


    for ip_range in sg_row[SG_IP_RANGE_KEY]:

        ip, cidr, net_addr = get_ip_range_info(ip_range[SG_CIDRIP_KEY])

        for permit_ip_range in permit_ip_ranges:

            try:
                permit_ip, permit_cidr, permit_net_addr = get_ip_range_info(permit_ip_range)

                if len(net_addr) < permit_cidr:
                    raise NotPermitException("Don't permit {}/{}".format(ip, cidr))

                if net_addr[:permit_cidr] == permit_net_addr:
                    return True
                else:
                    raise NotPermitException("Don't permit {}/{}".format(ip, cidr))

            except Exception as e:
                print(e.args)


    # Not match permit ip range.
    return False
        

def is_permit_sg_src(sg_row, permit_ip_ranges):
    """
    To check whether all of security group row is permitted.
    For ingress security group.
    """

    print('is_permit_sg_src: {}'.format(sg_row[SG_GROUP_PAIR_KEY]))

    global g_checked_sg_ids

    if SG_GROUP_PAIR_KEY in sg_row and sg_row[SG_GROUP_PAIR_KEY]:

        for sg_src in sg_row[SG_GROUP_PAIR_KEY]:
            group_id = sg_src[SG_GROUP_ID_KEY]

            if group_id in g_checked_sg_ids:
                continue
            else:
                g_checked_sg_ids.append(group_id)

            if not is_permit_sg(group_id, permit_ip_ranges):
                print("Don't permit {}".format(group_id))
                return False

    return True


def get_ip_range_info(ip_range):
    """
    Example:
      input: '10.0.0.1/24'
      return '10.0.0.0', 24, '000010100000000000000000' 
    """
    ip, cidr = ip_range.split('/')[0], int(ip_range.split('/')[1])
    ip_bin = ''.join(map(lambda s: format(int(s), '08b'), ip.split('.')))
    net_addr = ip_bin[:cidr]

    return (ip, cidr, net_addr)


def lambda_handler(event, context):
    """
    lambda_handler
    """

    invoking_event = json.loads(event['invokingEvent'])
    configuration_item = invoking_event["configurationItem"]
    rule_parameters = json.loads(event["ruleParameters"])


    global g_debug_enabled

    if DEBUG in rule_parameters:
        g_debug_enabled = True if rule_parameters[DEBUG].lower() == 'true' else False
    
    if g_debug_enabled:
        print("Received event: " + json.dumps(event, indent=2))


    if PERMIT_IP_RANGES in rule_parameters:
        permit_ip_ranges = list(map(lambda s: s.strip(), rule_parameters[PERMIT_IP_RANGES].split(',')))
    else:
        raise Exception("Must set parameter {}".format(PERMIT_IP_RANGES))


    evaluation = evaluate_compliance(configuration_item, permit_ip_ranges)

    config = boto3.client('config')

    response = config.put_evaluations(
       Evaluations=[
           {
               'ComplianceResourceType': invoking_event['configurationItem']['resourceType'],
               'ComplianceResourceId': invoking_event['configurationItem']['resourceId'],
               'ComplianceType': evaluation["compliance_type"],
               "Annotation": evaluation["annotation"],
               'OrderingTimestamp': invoking_event['configurationItem']['configurationItemCaptureTime']
           },
       ],
       ResultToken=event['resultToken'])

