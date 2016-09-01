import json
import urllib
import boto3
import gzip
import uuid
from datetime import date

print('Loading function')

dynamodb_conn = boto3.client('dynamodb')
s3 = boto3.resource('s3')
client = boto3.client('sns')
arn = 'arn:aws:sns:us-east-1:1234567891011:Innovation_Instance_Notification'
arn_devops = 'arn:aws:sns:us-east-1:1234567891011:CloudTrail_Lambda_Notification'
random=str(uuid.uuid4())
item={}
item={'ResourceId':{},'Date':{},'Account':{},'Region':{},'CreatedBy':{},'Type':{}}
item['Date']['S']=date.today().strftime('%d-%m-%Y')
temp_file='/tmp/temp_' + random + '.gz'
def lambda_handler(event, context):
    #print("Received event: " + json.dumps(event, indent=2))
    bucket = event['Records'][0]['s3']['bucket']['name']
    key = urllib.unquote_plus(event['Records'][0]['s3']['object']['key']).decode('utf8')
    string=''
    sub=''
    try:
        response=s3.meta.client.download_file(bucket,key,temp_file)
        with gzip.open(temp_file, 'rb') as f:
                file_content = f.read()
        file_json=json.loads(file_content)
        for i in file_json.get('Records'):
                if 'AuthorizeSecurityGroup' in i.get('eventName'):
                        sub = 'Security group Rule with 0.0.0.0/0'
                        request = i.get('requestParameters')
                        string1='New Security group Rule Alert' + '\n'
                        if '0.0.0.0/0' in str(request):
                                string1=string1 + "EventTime  : " + str(i.get('eventTime')) + '\n'
                                string1=string1 + "Security Group : " + str(i.get('requestParameters').get('groupId')) + '\n'
                                string1=string1 + "Region : " + str(i.get('awsRegion')) + '\n'
                                string1=string1 + "User : " + str(i.get('userIdentity').get('userName')) + '\n'
                                string1=string1 + "Account : " + str(i.get('userIdentity').get('accountId')) + '\n'
                                for rule in i.get('requestParameters').get('ipPermissions').get('items'):
                                    if '0.0.0.0/0' in str(rule):
                                        fromport=rule.get('fromPort')
                                        toport=rule.get('toPort')
                                        ipRange=rule.get('ipRanges').get('items')[0]
                                        ipProtocol=rule.get('ipProtocol')
                                        string1=string1 + "FromPort : " + str(fromport) + '\n'
                                        string1=string1 + "ToPort : " + str(toport) + '\n'
                                        string1=string1 + "ipProtocol : " + str(ipProtocol) + '\n'
                                        string1=string1 + "IpRange : " + str(ipRange) + '\n'
                                        string1=string1 + "--------------------------" + '\n'
                                        publication = client.publish(TopicArn=arn,Subject=sub,Message=str(string1))
                if 'CreateNetworkAclEntry' in i.get('eventName'):
                        string2='New Network ACL Rule Alert' + '\n'
                        sub = 'Network ACL Rule with 0.0.0.0/0'
                        request = i.get('requestParameters')
                        if '0.0.0.0/0' in str(request):
                                string2=string2 + "EventTime  : " + str(i.get('eventTime')) + '\n'
                                string2=string2 + "Network ACL : " + str(i.get('requestParameters').get('networkAclId')) + '\n'
                                string2=string2 + "Region : " + str(i.get('awsRegion')) + '\n'
                                string2=string2 + "User : " + str(i.get('userIdentity').get('userName')) + '\n'
                                string2=string2 + "Account : " + str(i.get('userIdentity').get('accountId')) + '\n'
                                #string=string + "Entry : " + str(i.get('requestParameters')) + '\n'
                                string2=string2 + "PortRange : " + str(i.get('requestParameters').get('portRange')) + '\n'
                                string2=string2 + "RuleAction : " + str(i.get('requestParameters').get('ruleAction')) + '\n'
                                string2=string2 + "CIDRBlock : " + str(i.get('requestParameters').get('cidrBlock')) + '\n'
                                string2=string2 + "--------------------------" + '\n'
                                publication = client.publish(TopicArn=arn,Subject=sub,Message=str(string2))
                if 'CreateUser' in i.get('eventName'):
                    sub = 'New IAM User Added'
                    request = i.get('requestParameters')
                    region=str(i.get('awsRegion'))
                    created_username = request.get('userName')
                    string3='New Resource Creations Alert' + '\n'
                    string3="The username " +str(created_username) + " is created by the below user" + '\n'
                    string3=string3 + "User : " + str(i.get('userIdentity').get('userName')) + '\n'
                    string3=string3 + "Account : " + str(i.get('userIdentity').get('accountId')) + '\n'
                    string3=string3 + "in the Region : " + region + '\n'
                    publication = client.publish(TopicArn=arn_devops,Subject=sub,Message=str(string3))
                    item['ResourceId']['S']=created_username
                    item['Type']['S']='IAMUser'
                    item['CreatedBy']['S']=str(i.get('userIdentity').get('userName'))
                    item['Account']['S']=str(i.get('userIdentity').get('accountId'))
                    item['Region']['S']=region
                    dynamodb_conn.put_item(TableName='innovation_cloudtrail_footprint',Item=item)
                    
                if 'RunInstances' in i.get('eventName'):
                    sub = 'New EC2 Instance Launched'
                    request = i.get('responseElements')
                    instanceid = request.get('instancesSet').get('items')[0].get('instanceId')
                    region=str(i.get('awsRegion'))
                    string4='New Resource Creations Alert' + '\n'
                    string4="The instance " +str(instanceid) + " is launched by the below user " + '\n'
                    string4=string4 + "User : " + str(i.get('userIdentity').get('userName')) + '\n'
                    string4=string4 + "Account : " + str(i.get('userIdentity').get('accountId')) + '\n'
                    string4=string4 + "in the Region : " + region + '\n'
                    publication = client.publish(TopicArn=arn_devops,Subject=sub,Message=str(string4))
                    item['ResourceId']['S']=instanceid
                    item['Type']['S']='EC2'
                    item['CreatedBy']['S']=str(i.get('userIdentity').get('userName'))
                    item['Account']['S']=str(i.get('userIdentity').get('accountId'))
                    item['Region']['S']=region
                    dynamodb_conn.put_item(TableName='innovation_cloudtrail_footprint',Item=item)
                if 'CreateLoadBalancer' in i.get('eventName'):
                    sub = 'New ELB Launched'
                    request = i.get('requestParameters')
                    created_elb = request.get('loadBalancerName')
                    region=str(i.get('awsRegion'))
                    string5='New Resource Creations Alert' + '\n'
                    string5="The ELB " +str(created_elb) + " is created by the below user" + '\n'
                    string5=string5 + "User : " + str(i.get('userIdentity').get('userName')) + '\n'
                    string5=string5 + "Account : " + str(i.get('userIdentity').get('accountId')) + '\n'
                    string5=string5 + "in the Region : " + region + '\n'
                    publication = client.publish(TopicArn=arn_devops,Subject=sub,Message=str(string5))
                    item['ResourceId']['S']=created_elb
                    item['Type']['S']='ELB'
                    item['CreatedBy']['S']=str(i.get('userIdentity').get('userName'))
                    item['Account']['S']=str(i.get('userIdentity').get('accountId'))
                    item['Region']['S']=region
                    dynamodb_conn.put_item(TableName='innovation_cloudtrail_footprint',Item=item)
                if 'CreateDBInstance' in i.get('eventName'):
                    sub = 'New RDS DB Instance Launched'
                    request = i.get('requestParameters')
                    created_rds_db = request.get('dBInstanceIdentifier')
                    region=str(i.get('awsRegion'))
                    string6='New Resource Creations Alert' + '\n'
                    string6="The RDS DB Instance " +str(created_rds_db) + " is created by the below user" + '\n'
                    string6=string6 + "User : " + str(i.get('userIdentity').get('userName')) + '\n'
                    string6=string6 + "Account : " + str(i.get('userIdentity').get('accountId')) + '\n'
                    string6=string6 + "in the Region : " + region + '\n'
                    publication = client.publish(TopicArn=arn_devops,Subject=sub,Message=str(string6))
                    item['ResourceId']['S']=created_rds_db
                    item['Type']['S']='RDS'
                    item['CreatedBy']['S']=str(i.get('userIdentity').get('userName'))
                    item['Account']['S']=str(i.get('userIdentity').get('accountId'))
                    item['Region']['S']=region
                    dynamodb_conn.put_item(TableName='innovation_cloudtrail_footprint',Item=item)
                if 'CreateSecurityGroup' in i.get('eventName'):
                    sub = 'New Security Group Created'
                    request = i.get('responseElements')
                    securitygroup_id=request.get('groupId')
                    region=str(i.get('awsRegion'))
                    string7='New Resource Creations Alert' + '\n'
                    string7="The Security Group " +str(securitygroup_id) + " is created by the below user" + '\n'
                    string7=string7 + "User : " + str(i.get('userIdentity').get('userName')) + '\n'
                    string7=string7 + "Account : " + str(i.get('userIdentity').get('accountId')) + '\n'
                    string7=string7 + "in the Region : " + region + '\n'
                    publication = client.publish(TopicArn=arn_devops,Subject=sub,Message=str(string7))
                    item['ResourceId']['S']=securitygroup_id
                    item['Type']['S']='SecurityGroup'
                    item['CreatedBy']['S']=str(i.get('userIdentity').get('userName'))
                    item['Account']['S']=str(i.get('userIdentity').get('accountId'))
                    item['Region']['S']=region
                    dynamodb_conn.put_item(TableName='innovation_cloudtrail_footprint',Item=item)
    except Exception as e:
        print(e)
        raise e
