"""AWS CLI command cheatsheet for quick reference."""

AWS_CLI_CHEATSHEET = {
    "CloudFormation": [
        "aws cloudformation list-stacks",
        "aws cloudformation describe-stacks --stack-name <name>",
        "aws cloudformation create-stack --stack-name <name> --template-body file://template.yml",
        "aws cloudformation update-stack --stack-name <name> --template-body file://template.yml",
        "aws cloudformation delete-stack --stack-name <name>",
    ],
    "CloudFront": [
        "aws cloudfront list-distributions",
        "aws cloudfront create-invalidation --distribution-id <id> --paths '/*'",
        "aws cloudfront get-distribution-config --id <id>",
    ],
    "CloudTrail": [
        "aws cloudtrail describe-trails",
        "aws cloudtrail lookup-events --max-results 20",
        "aws cloudtrail start-logging --name <trail-name>",
    ],
    "CloudWatch Logs": [
        "aws logs tail /aws/lambda/function-name --follow",
        "aws logs describe-log-groups",
        "aws logs describe-log-streams --log-group-name <name>",
    ],
    "CloudWatch Metrics": [
        "aws cloudwatch list-metrics --namespace AWS/EC2",
        "aws cloudwatch get-metric-statistics --namespace AWS/EC2 --metric-name CPUUtilization --dimensions Name=InstanceId,Value=<id> --start-time <iso> --end-time <iso> --period 300 --statistics Average",
        "aws cloudwatch describe-alarms",
    ],
    "DynamoDB": [
        "aws dynamodb list-tables",
        "aws dynamodb describe-table --table-name <name>",
        "aws dynamodb scan --table-name <name>",
        "aws dynamodb update-table --table-name <name> --provisioned-throughput ReadCapacityUnits=5,WriteCapacityUnits=5",
    ],
    "EC2": [
        "aws ec2 describe-instances",
        "aws ec2 start-instances --instance-ids i-xxxxx",
        "aws ec2 stop-instances --instance-ids i-xxxxx",
        "aws ec2 reboot-instances --instance-ids i-xxxxx",
        "aws ec2 describe-security-groups",
        "aws ec2 describe-vpcs",
        "aws ec2 describe-subnets",
        "aws ec2 create-image --instance-id i-xxxxx --name <image-name>",
    ],
    "ECR": [
        "aws ecr describe-repositories",
        "aws ecr get-login-password | docker login --username AWS --password-stdin <account>.dkr.ecr.<region>.amazonaws.com",
        "aws ecr list-images --repository-name <repo>",
        "aws ecr batch-delete-image --repository-name <repo> --image-ids imageTag=<tag>",
    ],
    "ECS": [
        "aws ecs list-clusters",
        "aws ecs list-services --cluster <cluster>",
        "aws ecs describe-services --cluster <cluster> --services <service>",
        "aws ecs update-service --cluster <cluster> --service <service> --force-new-deployment",
    ],
    "EKS": [
        "aws eks list-clusters",
        "aws eks describe-cluster --name <cluster>",
        "aws eks update-kubeconfig --name <cluster>",
    ],
    "Glue": [
        "aws glue get-databases",
        "aws glue get-tables --database-name <db>",
        "aws glue start-job-run --job-name <job>",
    ],
    "IAM": [
        "aws iam list-users",
        "aws iam list-roles",
        "aws iam get-user",
        "aws iam list-policies",
        "aws iam attach-role-policy --role-name <role> --policy-arn <arn>",
    ],
    "Identity/STS": [
        "aws sts get-caller-identity",
        "aws sts assume-role --role-arn <arn> --role-session-name <name>",
        "aws sts get-session-token",
    ],
    "Kinesis": [
        "aws kinesis list-streams",
        "aws kinesis describe-stream --stream-name <name>",
        "aws kinesis get-shard-iterator --stream-name <name> --shard-id <id> --shard-iterator-type TRIM_HORIZON",
    ],
    "KMS": [
        "aws kms list-keys",
        "aws kms describe-key --key-id <key-id>",
        "aws kms encrypt --key-id <key-id> --plaintext fileb://data.txt --output text --query CiphertextBlob",
    ],
    "Lambda": [
        "aws lambda list-functions",
        "aws lambda invoke --function-name <name> output.txt",
        "aws lambda get-function --function-name <name>",
        "aws lambda update-function-code --function-name <name> --zip-file fileb://function.zip",
    ],
    "Organizations": [
        "aws organizations list-accounts",
        "aws organizations describe-organization",
        "aws organizations list-parents --child-id <account-id>",
    ],
    "RDS": [
        "aws rds describe-db-instances",
        "aws rds describe-db-clusters",
        "aws rds create-db-snapshot --db-instance-identifier <id> --db-snapshot-identifier <snapshot>",
    ],
    "Redshift": [
        "aws redshift describe-clusters",
        "aws redshift describe-snapshot-schedules",
        "aws redshift create-cluster-snapshot --cluster-identifier <id> --snapshot-identifier <snapshot>",
    ],
    "Route53": [
        "aws route53 list-hosted-zones",
        "aws route53 list-resource-record-sets --hosted-zone-id <id>",
        "aws route53 change-resource-record-sets --hosted-zone-id <id> --change-batch file://change.json",
    ],
    "S3": [
        "aws s3 ls",
        "aws s3 ls s3://bucket-name",
        "aws s3 cp file.txt s3://bucket/",
        "aws s3 cp s3://bucket/file.txt .",
        "aws s3 sync ./dir s3://bucket/",
        "aws s3 mb s3://bucket-name",
        "aws s3 rb s3://bucket-name --force",
        "aws s3 rm s3://bucket/file.txt",
    ],
    "Secrets Manager": [
        "aws secretsmanager list-secrets",
        "aws secretsmanager get-secret-value --secret-id <name>",
        "aws secretsmanager update-secret --secret-id <name> --secret-string '<json>'",
    ],
    "SNS": [
        "aws sns list-topics",
        'aws sns publish --topic-arn <arn> --message "Hello"',
        "aws sns subscribe --topic-arn <arn> --protocol email --notification-endpoint <email>",
    ],
    "SQS": [
        "aws sqs list-queues",
        "aws sqs send-message --queue-url <url> --message-body 'Hello'",
        "aws sqs receive-message --queue-url <url>",
        "aws sqs purge-queue --queue-url <url>",
    ],
    "SSM": [
        "aws ssm describe-instance-information",
        "aws ssm get-parameter --name <name> --with-decryption",
        "aws ssm start-session --target <instance-id>",
        "aws ssm send-command --document-name AWS-RunShellScript --targets Key=instanceids,Values=<id> --parameters commands=['uptime']",
    ],
    "Step Functions": [
        "aws stepfunctions list-state-machines",
        "aws stepfunctions describe-state-machine --state-machine-arn <arn>",
        "aws stepfunctions start-execution --state-machine-arn <arn> --input file://input.json",
    ],
}

AWS_CLI_COMMANDS = [cmd for cmds in AWS_CLI_CHEATSHEET.values() for cmd in cmds]

COMMAND_CATEGORIES = {}
for category, commands in AWS_CLI_CHEATSHEET.items():
    for cmd in commands:
        COMMAND_CATEGORIES[cmd] = category
