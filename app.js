/**
 * TRUSTNOX — Detecting Excessive Cloud Permissions
 * Interactive Web Application Core Controller & Visualization Engine
 */

// Application State
let appData = null;
let currentTab = 'dashboard';
let selectedIdentityId = 'developer-user';
let activeEscalationScenario = 'chain-1';
let scanInterval = null;
let currentRemediationTarget = null;

// Initial IAM Data Fallback if fetching external file is blocked by browser file:// restrictions
const EMBEDDED_IAM_DATA = {
  "scan_metadata": {
    "account_id": "892147365012",
    "cloud_provider": "AWS",
    "region": "us-east-1 (N. Virginia)",
    "environment": "Production / Core-Cloud-VPC",
    "scan_timestamp": "2026-10-03T13:45:00Z",
    "total_identities": 25,
    "high_risk_count": 6,
    "medium_risk_count": 9,
    "low_risk_count": 10,
    "unused_accounts_count": 4,
    "escalation_paths_count": 3
  },
  "identities": [
    {
      "id": "id-001",
      "name": "developer-user",
      "type": "User",
      "arn": "arn:aws:iam::892147365012:user/developer-user",
      "permissions_count": 18,
      "last_used": "2 hours ago",
      "last_used_days": 0.08,
      "risk_level": "High",
      "risk_score": 87,
      "status": "Active",
      "is_unused": false,
      "has_wildcard": false,
      "has_admin": false,
      "has_passrole": true,
      "has_assumerole": true,
      "in_escalation_path": true,
      "escalation_details": "Can pass deploy-role to EC2 and assume admin-role via privilege chain.",
      "permissions": [
        { "action": "iam:PassRole", "category": "IAM", "is_dangerous": true, "reason": "Privilege escalation vector - allows passing roles with higher privileges to compute resources." },
        { "action": "s3:GetObject", "category": "S3", "is_dangerous": false, "reason": "Standard object read permission." },
        { "action": "ec2:StartInstances", "category": "EC2", "is_dangerous": false, "reason": "Basic infrastructure lifecycle control." },
        { "action": "sts:AssumeRole", "category": "STS", "is_dangerous": true, "reason": "Allows assuming target roles across environments." },
        { "action": "ec2:DescribeInstances", "category": "EC2", "is_dangerous": false, "reason": "Read-only compute inspection." },
        { "action": "s3:ListBucket", "category": "S3", "is_dangerous": false, "reason": "Bucket metadata inspection." },
        { "action": "cloudwatch:GetMetricData", "category": "CloudWatch", "is_dangerous": false, "reason": "Standard observability read." },
        { "action": "logs:FilterLogEvents", "category": "CloudWatch", "is_dangerous": false, "reason": "Telemetry querying." }
      ],
      "risk_reasons": [
        "Dangerous permission 'iam:PassRole' detected without resource boundary constraint.",
        "Privilege escalation path identified: reaches 'admin-role' through intermediate 'deploy-role'.",
        "Broad 'sts:AssumeRole' permission allows pivoting across roles.",
        "Permissions exceed expected engineering tier requirements."
      ],
      "remediation": {
        "problem": "Has iam:PassRole permission.",
        "fix": "Remove iam:PassRole unless specifically required.",
        "policy_diff": "- \"Action\": \"iam:PassRole\",\n- \"Resource\": \"*\"\n+ \"Action\": \"ec2:Describe*\",\n+ \"Resource\": \"arn:aws:ec2:*:*:instance/*\""
      }
    },
    {
      "id": "id-002",
      "name": "data-analyst",
      "type": "User",
      "arn": "arn:aws:iam::892147365012:user/data-analyst",
      "permissions_count": 8,
      "last_used": "Today",
      "last_used_days": 0.2,
      "risk_level": "Low",
      "risk_score": 28,
      "status": "Active",
      "is_unused": false,
      "has_wildcard": false,
      "has_admin": false,
      "has_passrole": false,
      "has_assumerole": false,
      "in_escalation_path": false,
      "permissions": [
        { "action": "athena:StartQueryExecution", "category": "Athena", "is_dangerous": false, "reason": "Required for analytical queries." },
        { "action": "athena:GetQueryResults", "category": "Athena", "is_dangerous": false, "reason": "Fetching query outputs." },
        { "action": "s3:GetObject", "category": "S3", "is_dangerous": false, "reason": "Read access strictly scoped to data warehouse bucket." },
        { "action": "s3:ListBucket", "category": "S3", "is_dangerous": false, "reason": "Listing analytical warehouse keys." },
        { "action": "glue:GetTable", "category": "Glue", "is_dangerous": false, "reason": "Catalog metadata lookup." },
        { "action": "quicksight:DescribeDashboard", "category": "QuickSight", "is_dangerous": false, "reason": "BI dashboard rendering." }
      ],
      "risk_reasons": [
        "Access strictly matches assigned analytical duties.",
        "MFA enforced on all interactive sessions.",
        "Activity audited regularly via AWS CloudTrail."
      ],
      "remediation": {
        "problem": "None. Identity follows least-privilege baseline.",
        "fix": "Maintain current read-only policies and quarterly credential rotation.",
        "policy_diff": "No changes needed. Baseline compliant."
      }
    },
    {
      "id": "id-003",
      "name": "deploy-role",
      "type": "Role",
      "arn": "arn:aws:iam::892147365012:role/deploy-role",
      "permissions_count": 25,
      "last_used": "1 hour ago",
      "last_used_days": 0.04,
      "risk_level": "Medium",
      "risk_score": 72,
      "status": "Active",
      "is_unused": false,
      "has_wildcard": true,
      "has_admin": false,
      "has_passrole": false,
      "has_assumerole": true,
      "in_escalation_path": true,
      "escalation_details": "Intermediate pivot in the Developer -> Admin escalation chain.",
      "permissions": [
        { "action": "sts:AssumeRole", "category": "STS", "is_dangerous": true, "reason": "Broad assume role trust relationship." },
        { "action": "ec2:*", "category": "EC2", "is_dangerous": true, "reason": "Wildcard action across all EC2 APIs." },
        { "action": "elasticloadbalancing:*", "category": "ELB", "is_dangerous": false, "reason": "Deployment load balancer reconfiguration." },
        { "action": "s3:PutObject", "category": "S3", "is_dangerous": false, "reason": "Artifact uploading." },
        { "action": "iam:GetRole", "category": "IAM", "is_dangerous": false, "reason": "Role metadata query." }
      ],
      "risk_reasons": [
        "Wildcard action 'ec2:*' grants over 300 individual API calls.",
        "Overly permissive trust relationship allows developer-user assumption.",
        "Missing session duration policy caps."
      ],
      "remediation": {
        "problem": "Contains ec2:* wildcard and can assume admin-role.",
        "fix": "Replace wildcard ec2:* with specific actions (ec2:RunInstances, ec2:DescribeInstances) and restrict target role assumption.",
        "policy_diff": "- \"Action\": \"ec2:*\"\n+ \"Action\": [\"ec2:RunInstances\", \"ec2:DescribeInstances\", \"ec2:StopInstances\"]"
      }
    },
    {
      "id": "id-004",
      "name": "old-admin",
      "type": "User",
      "arn": "arn:aws:iam::892147365012:user/old-admin",
      "permissions_count": 42,
      "last_used": "120 days ago",
      "last_used_days": 120,
      "risk_level": "High",
      "risk_score": 95,
      "status": "Inactive",
      "is_unused": true,
      "has_wildcard": true,
      "has_admin": true,
      "has_passrole": true,
      "has_assumerole": true,
      "in_escalation_path": false,
      "permissions": [
        { "action": "*", "category": "Admin", "is_dangerous": true, "reason": "Root-equivalent wildcard permission across all cloud services." },
        { "action": "iam:*", "category": "IAM", "is_dangerous": true, "reason": "Full IAM manipulation including user creation and credential injection." },
        { "action": "sts:AssumeRole", "category": "STS", "is_dangerous": true, "reason": "Cross-account escalation capabilities." }
      ],
      "risk_reasons": [
        "Dormant account inactive for 120 days retains full administrative access.",
        "Full root-equivalent wildcard '*' permission policy attached.",
        "High risk of credential theft via abandoned access keys or stale credentials.",
        "Zero MFA logins recorded in trailing 90-day telemetry."
      ],
      "remediation": {
        "problem": "Inactive account with admin permissions.",
        "fix": "Disable the account and remove unnecessary permissions.",
        "policy_diff": "# Action: Revoke Access Keys & Detach AdministratorAccess\n- Action: \"*\"\n- Resource: \"*\"\n+ Status: Account Disabled (AWS IAM Login Profile Deleted)"
      }
    },
    {
      "id": "id-005",
      "name": "wildcard-role",
      "type": "Role",
      "arn": "arn:aws:iam::892147365012:role/wildcard-role",
      "permissions_count": 38,
      "last_used": "5 hours ago",
      "last_used_days": 0.21,
      "risk_level": "High",
      "risk_score": 82,
      "status": "Active",
      "is_unused": false,
      "has_wildcard": true,
      "has_admin": false,
      "has_passrole": true,
      "has_assumerole": false,
      "in_escalation_path": false,
      "permissions": [
        { "action": "s3:*", "category": "S3", "is_dangerous": true, "reason": "Wildcard access to all buckets including sensitive backups and logs." },
        { "action": "dynamodb:*", "category": "DynamoDB", "is_dangerous": true, "reason": "Wildcard access permits dropping tables and bulk data exfiltration." },
        { "action": "iam:PassRole", "category": "IAM", "is_dangerous": true, "reason": "Can pass execution roles to serverless functions." }
      ],
      "risk_reasons": [
        "Uses wildcard (*) actions across multiple critical data services.",
        "Violates CIS AWS Foundations Benchmark 1.16.",
        "Enables potential data destruction and exfiltration."
      ],
      "remediation": {
        "problem": "Uses wildcard (*) actions.",
        "fix": "Replace wildcard permissions with specific required actions.",
        "policy_diff": "- \"Action\": [\"s3:*\", \"dynamodb:*\"],\n+ \"Action\": [\"s3:GetObject\", \"s3:PutObject\", \"dynamodb:GetItem\", \"dynamodb:PutItem\"]"
      }
    },
    {
      "id": "id-006",
      "name": "old-developer",
      "type": "User",
      "arn": "arn:aws:iam::892147365012:user/old-developer",
      "permissions_count": 22,
      "last_used": "120 days ago",
      "last_used_days": 120,
      "risk_level": "High",
      "risk_score": 85,
      "status": "Inactive",
      "is_unused": true,
      "has_wildcard": false,
      "has_admin": false,
      "has_passrole": true,
      "has_assumerole": true,
      "in_escalation_path": false,
      "permissions": [
        { "action": "iam:PassRole", "category": "IAM", "is_dangerous": true, "reason": "Privilege escalation vector." },
        { "action": "ec2:RunInstances", "category": "EC2", "is_dangerous": false, "reason": "Compute provisioning." },
        { "action": "s3:ListAllMyBuckets", "category": "S3", "is_dangerous": false, "reason": "Global bucket enumeration." }
      ],
      "risk_reasons": [
        "Account inactive for 120 days with unrotated access keys.",
        "Has dangerous PassRole permissions attached directly."
      ],
      "remediation": {
        "problem": "Stale developer identity dormant for 4 months.",
        "fix": "Disable console login profile, delete active access keys, archive audit log.",
        "policy_diff": "- \"Effect\": \"Allow\"\n+ \"Status\": \"Disabled\""
      }
    },
    {
      "id": "id-007",
      "name": "test-user",
      "type": "User",
      "arn": "arn:aws:iam::892147365012:user/test-user",
      "permissions_count": 14,
      "last_used": "90 days ago",
      "last_used_days": 90,
      "risk_level": "Medium",
      "risk_score": 64,
      "status": "Inactive",
      "is_unused": true,
      "has_wildcard": false,
      "has_admin": false,
      "has_passrole": false,
      "has_assumerole": false,
      "in_escalation_path": false,
      "permissions": [
        { "action": "sqs:ReceiveMessage", "category": "SQS", "is_dangerous": false, "reason": "Queue polling." },
        { "action": "sns:Publish", "category": "SNS", "is_dangerous": false, "reason": "Topic notifications." },
        { "action": "s3:PutObject", "category": "S3", "is_dangerous": false, "reason": "Test file drops." }
      ],
      "risk_reasons": [
        "Unused test account forgotten after QA cycle (90 days inactive).",
        "Retains write permissions into production shared buckets."
      ],
      "remediation": {
        "problem": "Test account inactive for 90 days.",
        "fix": "Decommission temporary testing identity and purge associated credentials.",
        "policy_diff": "- Identity: test-user\n+ Action: DeleteUser / PurgeCredentials"
      }
    },
    {
      "id": "id-008",
      "name": "inactive-admin",
      "type": "User",
      "arn": "arn:aws:iam::892147365012:user/inactive-admin",
      "permissions_count": 39,
      "last_used": "180 days ago",
      "last_used_days": 180,
      "risk_level": "High",
      "risk_score": 98,
      "status": "Inactive",
      "is_unused": true,
      "has_wildcard": true,
      "has_admin": true,
      "has_passrole": true,
      "has_assumerole": true,
      "in_escalation_path": false,
      "permissions": [
        { "action": "*", "category": "Admin", "is_dangerous": true, "reason": "Full administrative power across all regions." },
        { "action": "iam:CreateAccessKey", "category": "IAM", "is_dangerous": true, "reason": "Can generate persistent backdoor keys." }
      ],
      "risk_reasons": [
        "Dormant for half a year (180 days) with full administrative privileges.",
        "Represents severe risk for account takeover and undetected persistence.",
        "Bypasses zero-trust governance controls."
      ],
      "remediation": {
        "problem": "Critically dormant admin user (180 days) with root-equivalent power.",
        "fix": "Disable identity immediately, invalidate all session tokens and keys.",
        "policy_diff": "- Attachment: arn:aws:iam::aws:policy/AdministratorAccess\n+ UserStatus: Deactivated"
      }
    },
    {
      "id": "id-009",
      "name": "admin-role",
      "type": "Role",
      "arn": "arn:aws:iam::892147365012:role/admin-role",
      "permissions_count": 52,
      "last_used": "10 minutes ago",
      "last_used_days": 0.007,
      "risk_level": "High",
      "risk_score": 89,
      "status": "Active",
      "is_unused": false,
      "has_wildcard": true,
      "has_admin": true,
      "has_passrole": true,
      "has_assumerole": true,
      "in_escalation_path": true,
      "escalation_details": "Target role in the Developer User escalation path.",
      "permissions": [
        { "action": "*", "category": "Admin", "is_dangerous": true, "reason": "Full cloud control." },
        { "action": "iam:*", "category": "IAM", "is_dangerous": true, "reason": "Unrestricted IAM governance." }
      ],
      "risk_reasons": [
        "Trust policy allows assume role from deploy-role without condition keys.",
        "Overly permissive role reachable by lower-tier identities."
      ],
      "remediation": {
        "problem": "Trust policy permits assumption by over-privileged deploy-role.",
        "fix": "Require MFA and external ID, and restrict principal ARN to hardware-token admins.",
        "policy_diff": "- \"Principal\": {\"AWS\": \"*\"}\n+ \"Principal\": {\"AWS\": \"arn:aws:iam::892147365012:role/SecOpsMFA\"}"
      }
    },
    {
      "id": "id-010",
      "name": "ci-cd-runner",
      "type": "Role",
      "arn": "arn:aws:iam::892147365012:role/ci-cd-runner",
      "permissions_count": 27,
      "last_used": "30 minutes ago",
      "last_used_days": 0.02,
      "risk_level": "Medium",
      "risk_score": 68,
      "status": "Active",
      "is_unused": false,
      "has_wildcard": true,
      "has_admin": false,
      "has_passrole": true,
      "has_assumerole": false,
      "in_escalation_path": false,
      "permissions": [
        { "action": "ecs:*", "category": "ECS", "is_dangerous": true, "reason": "Wildcard container orchestration." },
        { "action": "ecr:*", "category": "ECR", "is_dangerous": false, "reason": "Container registry push/pull." },
        { "action": "iam:PassRole", "category": "IAM", "is_dangerous": true, "reason": "Can pass task execution roles." }
      ],
      "risk_reasons": [
        "Contains ecs:* wildcard and unconstrained iam:PassRole for task execution roles."
      ],
      "remediation": {
        "problem": "Unscoped PassRole allows injecting arbitrary roles into ECS containers.",
        "fix": "Limit PassRole to arn:aws:iam::*:role/ecs-task-execution-* only.",
        "policy_diff": "- \"Resource\": \"*\"\n+ \"Resource\": \"arn:aws:iam::892147365012:role/ecs-task-execution-*\""
      }
    },
    {
      "id": "id-011",
      "name": "lambda-exec-worker",
      "type": "Role",
      "arn": "arn:aws:iam::892147365012:role/lambda-exec-worker",
      "permissions_count": 12,
      "last_used": "3 hours ago",
      "last_used_days": 0.12,
      "risk_level": "Low",
      "risk_score": 32,
      "status": "Active",
      "is_unused": false,
      "has_wildcard": false,
      "has_admin": false,
      "has_passrole": false,
      "has_assumerole": false,
      "in_escalation_path": false,
      "permissions": [
        { "action": "logs:CreateLogGroup", "category": "CloudWatch", "is_dangerous": false, "reason": "Standard execution logging." },
        { "action": "logs:CreateLogStream", "category": "CloudWatch", "is_dangerous": false, "reason": "Standard stream creation." },
        { "action": "logs:PutLogEvents", "category": "CloudWatch", "is_dangerous": false, "reason": "Emitting runtime logs." },
        { "action": "sqs:ReceiveMessage", "category": "SQS", "is_dangerous": false, "reason": "Trigger queue processing." }
      ],
      "risk_reasons": ["Follows standard AWS Lambda basic execution policy."],
      "remediation": { "problem": "None", "fix": "Compliant with least privilege.", "policy_diff": "No change." }
    },
    {
      "id": "id-012",
      "name": "backup-operator",
      "type": "User",
      "arn": "arn:aws:iam::892147365012:user/backup-operator",
      "permissions_count": 16,
      "last_used": "Yesterday",
      "last_used_days": 1.0,
      "risk_level": "Medium",
      "risk_score": 58,
      "status": "Active",
      "is_unused": false,
      "has_wildcard": true,
      "has_admin": false,
      "has_passrole": false,
      "has_assumerole": false,
      "in_escalation_path": false,
      "permissions": [
        { "action": "s3:ListAllMyBuckets", "category": "S3", "is_dangerous": false, "reason": "Backup inventory discovery." },
        { "action": "s3:GetObject", "category": "S3", "is_dangerous": false, "reason": "Backup extraction." },
        { "action": "glacier:*", "category": "Glacier", "is_dangerous": true, "reason": "Wildcard permissions over cold storage vaults." }
      ],
      "risk_reasons": ["Wildcard glacier:* action allows vault deletion."],
      "remediation": {
        "problem": "Wildcard access on Glacier service.",
        "fix": "Restrict to glacier:UploadArchive and glacier:InitiateJob.",
        "policy_diff": "- \"Action\": \"glacier:*\"\n+ \"Action\": [\"glacier:UploadArchive\", \"glacier:InitiateJob\"]"
      }
    },
    {
      "id": "id-013",
      "name": "billing-viewer",
      "type": "User",
      "arn": "arn:aws:iam::892147365012:user/billing-viewer",
      "permissions_count": 6,
      "last_used": "Today",
      "last_used_days": 0.3,
      "risk_level": "Low",
      "risk_score": 15,
      "status": "Active",
      "is_unused": false,
      "has_wildcard": false,
      "has_admin": false,
      "has_passrole": false,
      "has_assumerole": false,
      "in_escalation_path": false,
      "permissions": [
        { "action": "aws-portal:ViewBilling", "category": "Billing", "is_dangerous": false, "reason": "Cost dashboard view." },
        { "action": "ce:GetCostAndUsage", "category": "CostExplorer", "is_dangerous": false, "reason": "Reporting queries." }
      ],
      "risk_reasons": ["Well-scoped financial read-only identity."],
      "remediation": { "problem": "None", "fix": "Maintain baseline.", "policy_diff": "No change." }
    },
    {
      "id": "id-014",
      "name": "security-auditor",
      "type": "Role",
      "arn": "arn:aws:iam::892147365012:role/security-auditor",
      "permissions_count": 22,
      "last_used": "4 hours ago",
      "last_used_days": 0.16,
      "risk_level": "Low",
      "risk_score": 24,
      "status": "Active",
      "is_unused": false,
      "has_wildcard": false,
      "has_admin": false,
      "has_passrole": false,
      "has_assumerole": false,
      "in_escalation_path": false,
      "permissions": [
        { "action": "securityhub:GetFindings", "category": "SecurityHub", "is_dangerous": false, "reason": "Compliance posture telemetry." },
        { "action": "config:GetComplianceDetailsByConfigRule", "category": "Config", "is_dangerous": false, "reason": "Rule auditing." },
        { "action": "guardduty:ListDetectors", "category": "GuardDuty", "is_dangerous": false, "reason": "Threat detection audit." }
      ],
      "risk_reasons": ["Uses AWS managed SecurityAudit policy without write or delete powers."],
      "remediation": { "problem": "None", "fix": "Compliant.", "policy_diff": "No change." }
    },
    {
      "id": "id-015",
      "name": "rds-admin",
      "type": "Role",
      "arn": "arn:aws:iam::892147365012:role/rds-admin",
      "permissions_count": 29,
      "last_used": "6 hours ago",
      "last_used_days": 0.25,
      "risk_level": "Medium",
      "risk_score": 62,
      "status": "Active",
      "is_unused": false,
      "has_wildcard": true,
      "has_admin": false,
      "has_passrole": false,
      "has_assumerole": false,
      "in_escalation_path": false,
      "permissions": [
        { "action": "rds:*", "category": "RDS", "is_dangerous": true, "reason": "Allows deleting DB clusters and modifying snapshot sharing." },
        { "action": "kms:Decrypt", "category": "KMS", "is_dangerous": false, "reason": "Storage key decryption." }
      ],
      "risk_reasons": ["Wildcard rds:* permission allows snapshot sharing to external malicious accounts."],
      "remediation": {
        "problem": "Unrestricted rds:* wildcard.",
        "fix": "Explicitly deny rds:ModifyDBSnapshotAttribute to block public database sharing.",
        "policy_diff": "+ \"Effect\": \"Deny\", \"Action\": \"rds:ModifyDBSnapshotAttribute\""
      }
    },
    {
      "id": "id-016",
      "name": "s3-sync-user",
      "type": "User",
      "arn": "arn:aws:iam::892147365012:user/s3-sync-user",
      "permissions_count": 9,
      "last_used": "1 hour ago",
      "last_used_days": 0.04,
      "risk_level": "Low",
      "risk_score": 19,
      "status": "Active",
      "is_unused": false,
      "has_wildcard": false,
      "has_admin": false,
      "has_passrole": false,
      "has_assumerole": false,
      "in_escalation_path": false,
      "permissions": [
        { "action": "s3:PutObject", "category": "S3", "is_dangerous": false, "reason": "Scoped to sync bucket prefix." },
        { "action": "s3:GetObject", "category": "S3", "is_dangerous": false, "reason": "Bucket synchronization." }
      ],
      "risk_reasons": ["Scoped cleanly to resource arn:aws:s3:::sync-data-prod/*."],
      "remediation": { "problem": "None", "fix": "Compliant.", "policy_diff": "No change." }
    },
    {
      "id": "id-017",
      "name": "monitoring-agent",
      "type": "Role",
      "arn": "arn:aws:iam::892147365012:role/monitoring-agent",
      "permissions_count": 11,
      "last_used": "15 minutes ago",
      "last_used_days": 0.01,
      "risk_level": "Low",
      "risk_score": 18,
      "status": "Active",
      "is_unused": false,
      "has_wildcard": false,
      "has_admin": false,
      "has_passrole": false,
      "has_assumerole": false,
      "in_escalation_path": false,
      "permissions": [
        { "action": "cloudwatch:PutMetricData", "category": "CloudWatch", "is_dangerous": false, "reason": "Metric collection." },
        { "action": "ec2:DescribeInstances", "category": "EC2", "is_dangerous": false, "reason": "Host tagging inspection." }
      ],
      "risk_reasons": ["Telemetry only, zero IAM or destructive API access."],
      "remediation": { "problem": "None", "fix": "Compliant.", "policy_diff": "No change." }
    },
    {
      "id": "id-018",
      "name": "intern-analyst",
      "type": "User",
      "arn": "arn:aws:iam::892147365012:user/intern-analyst",
      "permissions_count": 15,
      "last_used": "2 days ago",
      "last_used_days": 2.0,
      "risk_level": "Medium",
      "risk_score": 52,
      "status": "Active",
      "is_unused": false,
      "has_wildcard": false,
      "has_admin": false,
      "has_passrole": false,
      "has_assumerole": true,
      "in_escalation_path": false,
      "permissions": [
        { "action": "s3:GetObject", "category": "S3", "is_dangerous": false, "reason": "Standard reads." },
        { "action": "sts:AssumeRole", "category": "STS", "is_dangerous": true, "reason": "Can assume internal reporting role without condition." }
      ],
      "risk_reasons": ["Intern account assigned unconstrained sts:AssumeRole."],
      "remediation": {
        "problem": "sts:AssumeRole attached directly to junior intern.",
        "fix": "Remove sts:AssumeRole policy attachment.",
        "policy_diff": "- \"Action\": \"sts:AssumeRole\""
      }
    },
    {
      "id": "id-019",
      "name": "dns-manager-role",
      "type": "Role",
      "arn": "arn:aws:iam::892147365012:role/dns-manager-role",
      "permissions_count": 6,
      "last_used": "3 days ago",
      "last_used_days": 3.0,
      "risk_level": "Low",
      "risk_score": 22,
      "status": "Active",
      "is_unused": false,
      "has_wildcard": false,
      "has_admin": false,
      "has_passrole": false,
      "has_assumerole": false,
      "in_escalation_path": false,
      "permissions": [
        { "action": "route53:ChangeResourceRecordSets", "category": "Route53", "is_dangerous": false, "reason": "Scoped to specific application hosted zone." },
        { "action": "route53:ListHostedZones", "category": "Route53", "is_dangerous": false, "reason": "DNS listings." }
      ],
      "risk_reasons": ["Well-scoped DNS management role constrained by route53 conditions."],
      "remediation": {
        "problem": "None",
        "fix": "Compliant with baseline.",
        "policy_diff": "No change."
      }
    },
    {
      "id": "id-020",
      "name": "support-engineer",
      "type": "User",
      "arn": "arn:aws:iam::892147365012:user/support-engineer",
      "permissions_count": 21,
      "last_used": "5 hours ago",
      "last_used_days": 0.2,
      "risk_level": "Medium",
      "risk_score": 54,
      "status": "Active",
      "is_unused": false,
      "has_wildcard": false,
      "has_admin": false,
      "has_passrole": false,
      "has_assumerole": false,
      "in_escalation_path": false,
      "permissions": [
        { "action": "ec2:Describe*", "category": "EC2", "is_dangerous": false, "reason": "Support debugging." },
        { "action": "rds:Describe*", "category": "RDS", "is_dangerous": false, "reason": "Database health read." },
        { "action": "ssm:StartSession", "category": "SSM", "is_dangerous": true, "reason": "Can initiate interactive shell into production instances." }
      ],
      "risk_reasons": ["ssm:StartSession allows unmonitored command shell access on servers."],
      "remediation": {
        "problem": "Unrestricted SSM session initiation.",
        "fix": "Require session logging to encrypted S3 and approval workflow.",
        "policy_diff": "+ \"Condition\": {\"StringEquals\": {\"ssm:SessionDocumentAccessCheck\": \"true\"}}"
      }
    },
    {
      "id": "id-021",
      "name": "secret-rotation-lambda",
      "type": "Role",
      "arn": "arn:aws:iam::892147365012:role/secret-rotation-lambda",
      "permissions_count": 17,
      "last_used": "1 day ago",
      "last_used_days": 1.0,
      "risk_level": "Medium",
      "risk_score": 60,
      "status": "Active",
      "is_unused": false,
      "has_wildcard": false,
      "has_admin": false,
      "has_passrole": false,
      "has_assumerole": false,
      "in_escalation_path": false,
      "permissions": [
        { "action": "secretsmanager:GetSecretValue", "category": "SecretsManager", "is_dangerous": true, "reason": "Access to cleartext credentials." },
        { "action": "secretsmanager:PutSecretValue", "category": "SecretsManager", "is_dangerous": false, "reason": "Writing rotated credentials." }
      ],
      "risk_reasons": ["Target secrets ARN not restricted; can read master DB credentials."],
      "remediation": {
        "problem": "SecretsManager wildcard resource scope.",
        "fix": "Constrain Resource ARN strictly to rotation target secrets.",
        "policy_diff": "- \"Resource\": \"arn:aws:secretsmanager:*:*:secret:*\"\n+ \"Resource\": \"arn:aws:secretsmanager:*:*:secret:app/rotation/*\""
      }
    },
    {
      "id": "id-022",
      "name": "graphql-service-acc",
      "type": "Role",
      "arn": "arn:aws:iam::892147365012:role/graphql-service-acc",
      "permissions_count": 13,
      "last_used": "4 minutes ago",
      "last_used_days": 0.003,
      "risk_level": "Low",
      "risk_score": 22,
      "status": "Active",
      "is_unused": false,
      "has_wildcard": false,
      "has_admin": false,
      "has_passrole": false,
      "has_assumerole": false,
      "in_escalation_path": false,
      "permissions": [
        { "action": "dynamodb:Query", "category": "DynamoDB", "is_dangerous": false, "reason": "API query resolving." },
        { "action": "dynamodb:GetItem", "category": "DynamoDB", "is_dangerous": false, "reason": "Single entity fetching." }
      ],
      "risk_reasons": ["Tight scoping to application DynamoDB tables."],
      "remediation": { "problem": "None", "fix": "Compliant.", "policy_diff": "No change." }
    },
    {
      "id": "id-023",
      "name": "devops-engineer",
      "type": "User",
      "arn": "arn:aws:iam::892147365012:user/devops-engineer",
      "permissions_count": 28,
      "last_used": "3 hours ago",
      "last_used_days": 0.12,
      "risk_level": "Medium",
      "risk_score": 69,
      "status": "Active",
      "is_unused": false,
      "has_wildcard": true,
      "has_admin": false,
      "has_passrole": true,
      "has_assumerole": true,
      "in_escalation_path": true,
      "escalation_details": "Alternative escalation path via CloudFormation template injection.",
      "permissions": [
        { "action": "cloudformation:*", "category": "CloudFormation", "is_dangerous": true, "reason": "Can deploy stacks with arbitrary IAM roles." },
        { "action": "iam:PassRole", "category": "IAM", "is_dangerous": true, "reason": "Pass role to CloudFormation service." }
      ],
      "risk_reasons": [
        "CloudFormation wildcard with PassRole allows creating admin roles during stack deployment."
      ],
      "remediation": {
        "problem": "CloudFormation wildcard execution creates privilege escalation.",
        "fix": "Remove PassRole on admin roles, enforce stack policy controls.",
        "policy_diff": "- \"Action\": \"cloudformation:*\"\n+ \"Action\": [\"cloudformation:DescribeStacks\", \"cloudformation:CreateChangeSet\"]"
      }
    },
    {
      "id": "id-024",
      "name": "read-only-guest",
      "type": "User",
      "arn": "arn:aws:iam::892147365012:user/read-only-guest",
      "permissions_count": 5,
      "last_used": "Yesterday",
      "last_used_days": 1.2,
      "risk_level": "Low",
      "risk_score": 12,
      "status": "Active",
      "is_unused": false,
      "has_wildcard": false,
      "has_admin": false,
      "has_passrole": false,
      "has_assumerole": false,
      "in_escalation_path": false,
      "permissions": [
        { "action": "ec2:DescribeInstances", "category": "EC2", "is_dangerous": false, "reason": "Inventory read." },
        { "action": "s3:ListAllMyBuckets", "category": "S3", "is_dangerous": false, "reason": "Read list." }
      ],
      "risk_reasons": ["Strict read-only posture without sensitive service access."],
      "remediation": { "problem": "None", "fix": "Compliant.", "policy_diff": "No change." }
    },
    {
      "id": "id-025",
      "name": "finops-bot",
      "type": "Role",
      "arn": "arn:aws:iam::892147365012:role/finops-bot",
      "permissions_count": 7,
      "last_used": "1 hour ago",
      "last_used_days": 0.05,
      "risk_level": "Low",
      "risk_score": 16,
      "status": "Active",
      "is_unused": false,
      "has_wildcard": false,
      "has_admin": false,
      "has_passrole": false,
      "has_assumerole": false,
      "in_escalation_path": false,
      "permissions": [
        { "action": "ce:GetCostAndUsage", "category": "CostExplorer", "is_dangerous": false, "reason": "Cost anomaly detection." },
        { "action": "budgets:ViewBudget", "category": "Budgets", "is_dangerous": false, "reason": "Budget metrics." }
      ],
      "risk_reasons": ["Automated FinOps agent operating in strict least privilege."],
      "remediation": { "problem": "None", "fix": "Compliant.", "policy_diff": "No change." }
    }
  ],
  "escalation_chains": [
    {
      "id": "chain-1",
      "name": "Developer to Full Administrator Escalation",
      "severity": "CRITICAL",
      "risk_score": 96,
      "description": "A low-privileged developer user leverages unconstrained iam:PassRole to attach a high-privilege deployment role onto an EC2 compute instance, then uses that instance identity to assume admin-role with full cloud control.",
      "warning": "Privilege escalation detected",
      "recommendation": "Remove iam:PassRole from the developer-user.",
      "nodes": [
        { "id": "n1", "label": "Developer User", "type": "User", "risk": "High", "role_type": "source", "x": 120, "y": 270, "desc": "Low-level IAM identity with basic dev access" },
        { "id": "n2", "label": "iam:PassRole", "type": "Permission", "risk": "Critical", "role_type": "vector", "x": 290, "y": 270, "desc": "Unconstrained role passage vector" },
        { "id": "n3", "label": "Deploy Role", "type": "Role", "risk": "Medium", "role_type": "intermediate", "x": 470, "y": 270, "desc": "CI/CD server identity with broad EC2 permissions" },
        { "id": "n4", "label": "sts:AssumeRole", "type": "Permission", "risk": "Critical", "role_type": "vector", "x": 650, "y": 270, "desc": "Role assumption call bypassing cross-account boundaries" },
        { "id": "n5", "label": "Admin Role", "type": "Role", "risk": "High", "role_type": "target", "x": 830, "y": 270, "desc": "Target role with AdministratorAccess policy" },
        { "id": "n6", "label": "Full Control", "type": "Privilege", "risk": "High", "role_type": "impact", "x": 1010, "y": 270, "desc": "Root-equivalent administrative compromise (*:*)" }
      ],
      "edges": [
        { "from": "n1", "to": "n2", "label": "Executes" },
        { "from": "n2", "to": "n3", "label": "Attaches to compute" },
        { "from": "n3", "to": "n4", "label": "Invokes" },
        { "from": "n4", "to": "n5", "label": "Assumes" },
        { "from": "n5", "to": "n6", "label": "Grants Full Control" }
      ]
    },
    {
      "id": "chain-2",
      "name": "CloudFormation Template Role Injection",
      "severity": "HIGH",
      "risk_score": 88,
      "description": "devops-engineer uses cloudformation:CreateStack combined with iam:PassRole to deploy a CloudFormation template that provisions a backdoor administrator IAM access key.",
      "warning": "Infrastructure-as-Code Escalation detected",
      "recommendation": "Enforce Service-Linked Role boundaries and remove direct iam:PassRole for cloudformation.amazonaws.com.",
      "nodes": [
        { "id": "c2-n1", "label": "DevOps Engineer", "type": "User", "risk": "Medium", "role_type": "source", "x": 160, "y": 270, "desc": "DevOps account with template deployment permissions" },
        { "id": "c2-n2", "label": "cloudformation:CreateStack", "type": "Permission", "risk": "Critical", "role_type": "vector", "x": 420, "y": 270, "desc": "Stack creation permission" },
        { "id": "c2-n3", "label": "CFN Service Role", "type": "Role", "risk": "High", "role_type": "intermediate", "x": 680, "y": 270, "desc": "Privileged deployment worker" },
        { "id": "c2-n4", "label": "Backdoor Admin Key", "type": "Privilege", "risk": "High", "role_type": "impact", "x": 940, "y": 270, "desc": "Full Root Access Injection" }
      ],
      "edges": [
        { "from": "c2-n1", "to": "c2-n2", "label": "Dispatches template" },
        { "from": "c2-n2", "to": "c2-n3", "label": "Passes role" },
        { "from": "c2-n3", "to": "c2-n4", "label": "Provisions IAM admin" }
      ]
    },
    {
      "id": "chain-3",
      "name": "Lambda Execution Role Privilege Pivot",
      "severity": "HIGH",
      "risk_score": 84,
      "description": "An over-privileged developer updates Lambda function code using lambda:UpdateFunctionCode to execute arbitrary code with lambda-exec-worker's credentials, which possesses unmonitored STS AssumeRole capabilities.",
      "warning": "Serverless Escalation Vector detected",
      "recommendation": "Enforce code signing for Lambda functions and segregate deployment pipeline credentials.",
      "nodes": [
        { "id": "c3-n1", "label": "Junior Dev", "type": "User", "risk": "Medium", "role_type": "source", "x": 160, "y": 270, "desc": "Can update Lambda application code" },
        { "id": "c3-n2", "label": "lambda:UpdateFunctionCode", "type": "Permission", "risk": "High", "role_type": "vector", "x": 420, "y": 270, "desc": "Arbitrary code execution on compute" },
        { "id": "c3-n3", "label": "Lambda Execution Role", "type": "Role", "risk": "High", "role_type": "intermediate", "x": 680, "y": 270, "desc": "Serverless worker identity" },
        { "id": "c3-n4", "label": "Cross-Account Target", "type": "Privilege", "risk": "High", "role_type": "impact", "x": 940, "y": 270, "desc": "Pivots into staging and secrets store" }
      ],
      "edges": [
        { "from": "c3-n1", "to": "c3-n2", "label": "Uploads zip payload" },
        { "from": "c3-n2", "to": "c3-n3", "label": "Executes as role" },
        { "from": "c3-n3", "to": "c3-n4", "label": "Extracts credentials" }
      ]
    }
  ],
  "policy_raw_examples": {
    "developer-user": {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Sid": "DangerousPassRoleVector",
          "Effect": "Allow",
          "Action": [
            "iam:PassRole",
            "sts:AssumeRole"
          ],
          "Resource": "*",
          "Comment": "FLAGGED BY TRUSTNOX: Unconstrained PassRole and AssumeRole allow escalation to deploy-role and admin-role."
        },
        {
          "Sid": "StandardDevPermissions",
          "Effect": "Allow",
          "Action": [
            "s3:GetObject",
            "s3:ListBucket",
            "ec2:StartInstances",
            "ec2:DescribeInstances",
            "cloudwatch:GetMetricData",
            "logs:FilterLogEvents"
          ],
          "Resource": "*"
        }
      ]
    },
    "deploy-role": {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Sid": "BroadAssumeRolePolicy",
          "Effect": "Allow",
          "Action": "sts:AssumeRole",
          "Resource": "arn:aws:iam::892147365012:role/admin-role",
          "Comment": "FLAGGED BY TRUSTNOX: Overly permissive trust bridge to admin-role."
        },
        {
          "Sid": "EC2WildcardAccess",
          "Effect": "Allow",
          "Action": "ec2:*",
          "Resource": "*",
          "Comment": "FLAGGED BY TRUSTNOX: Over-privileged wildcard access to compute."
        }
      ]
    },
    "old-admin": {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Sid": "FullAdministratorAccess",
          "Effect": "Allow",
          "Action": "*",
          "Resource": "*",
          "Comment": "FLAGGED BY TRUSTNOX: Dormant identity (120 days inactive) retains full root access."
        }
      ]
    },
    "wildcard-role": {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Sid": "WildcardDataStores",
          "Effect": "Allow",
          "Action": [
            "s3:*",
            "dynamodb:*"
          ],
          "Resource": "*",
          "Comment": "FLAGGED BY TRUSTNOX: Wildcard permissions violate least-privilege standards."
        }
      ]
    }
  }
};

// Initialize Application
document.addEventListener('DOMContentLoaded', () => {
  // Deep clone to allow live state mutations (remediation, disabling accounts, etc.)
  appData = JSON.parse(JSON.stringify(EMBEDDED_IAM_DATA));
  initApp();
});

function initApp() {
  renderDashboardKPIs();
  renderIdentitiesTable();
  populateAnalyzerDropdown();
  loadAnalyzerData(selectedIdentityId);
  renderEscalationGraph(activeEscalationScenario);
  renderUnusedAccountsTable();
  renderRankedReportsTable('All');
  renderRecommendationsList();

  // Draw initial charts
  setTimeout(() => {
    drawDonutChart();
    drawHighRiskBarChart();
  }, 100);

  // Resize listener for responsive charts and graph
  window.addEventListener('resize', () => {
    drawDonutChart();
    drawHighRiskBarChart();
    renderEscalationGraph(activeEscalationScenario);
  });
}

/* ==========================================================================
   1. LOGIN PAGE CONTROLLER
   ========================================================================== */
function handleLoginSubmit(e) {
  e.preventDefault();
  const email = document.getElementById('login-email').value;
  completeLogin(email);
}

function handleDemoLogin() {
  document.getElementById('login-email').value = 'soc-analyst@trustnox.cloud';
  document.getElementById('login-password').value = 'SecuritySummitDemo2026!';
  setTimeout(() => {
    completeLogin('soc-analyst@trustnox.cloud');
  }, 250);
}

function completeLogin(email) {
  const loginScreen = document.getElementById('login-screen');
  const appContainer = document.getElementById('app-container');

  loginScreen.style.opacity = '0';
  loginScreen.style.transition = 'opacity 0.35s ease';

  setTimeout(() => {
    loginScreen.style.display = 'none';
    appContainer.style.display = 'flex';
    appContainer.style.opacity = '0';
    appContainer.style.transition = 'opacity 0.35s ease';

    setTimeout(() => {
      appContainer.style.opacity = '1';
      showToast(`Welcome, Cloud Security Analyst (${email}). IAM Telemetry loaded.`, 'success');
      drawDonutChart();
      drawHighRiskBarChart();
    }, 50);
  }, 350);
}

function handleLogout() {
  const loginScreen = document.getElementById('login-screen');
  const appContainer = document.getElementById('app-container');

  appContainer.style.opacity = '0';
  setTimeout(() => {
    appContainer.style.display = 'none';
    loginScreen.style.display = 'flex';
    loginScreen.style.opacity = '1';
    showToast('Logged out securely.', 'info');
  }, 300);
}

/* ==========================================================================
   NAVIGATION & TAB ROUTING
   ========================================================================== */
function switchTab(tabId, optionalFilter) {
  currentTab = tabId;

  // Update nav tabs
  document.querySelectorAll('.nav-tab').forEach(tab => {
    if (tab.dataset.tab === tabId) {
      tab.classList.add('active');
    } else {
      tab.classList.remove('active');
    }
  });

  // Update views
  document.querySelectorAll('.page-view').forEach(view => {
    view.classList.remove('active-page');
  });

  const targetView = document.getElementById(`view-${tabId}`);
  if (targetView) {
    targetView.classList.add('active-page');
  }

  // Handle contextual tab actions
  if (tabId === 'dashboard') {
    setTimeout(() => {
      drawDonutChart();
      drawHighRiskBarChart();
    }, 50);
  } else if (tabId === 'identities' && optionalFilter) {
    document.getElementById('filter-risk').value = optionalFilter;
    filterIdentitiesTable();
  } else if (tabId === 'graph') {
    setTimeout(() => {
      renderEscalationGraph(activeEscalationScenario);
    }, 50);
  }

  window.scrollTo({ top: 0, behavior: 'smooth' });
}

/* ==========================================================================
   2. DASHBOARD & KPIS
   ========================================================================== */
function renderDashboardKPIs() {
  const identities = appData.identities;
  const highRisk = identities.filter(i => i.risk_level === 'High').length;
  const medRisk = identities.filter(i => i.risk_level === 'Medium').length;
  const lowRisk = identities.filter(i => i.risk_level === 'Low').length;
  const unused = identities.filter(i => i.is_unused && i.status !== 'Disabled').length;
  const escalations = appData.escalation_chains.length;

  document.getElementById('kpi-total-val').textContent = identities.length;
  document.getElementById('kpi-high-val').textContent = highRisk;
  document.getElementById('kpi-med-val').textContent = medRisk;
  document.getElementById('kpi-low-val').textContent = lowRisk;
  document.getElementById('kpi-unused-val').textContent = unused;
  document.getElementById('kpi-escalation-val').textContent = escalations;
}

/* ==========================================================================
   10. SECURITY OVERVIEW CHARTS (NATIVE CANVAS - ZERO EXTERNAL DEPS)
   ========================================================================== */
function drawDonutChart() {
  const canvas = document.getElementById('risk-donut-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const dpr = window.devicePixelRatio || 1;
  const width = canvas.clientWidth || 220;
  const height = canvas.clientHeight || 220;

  canvas.width = width * dpr;
  canvas.height = height * dpr;
  ctx.scale(dpr, dpr);

  ctx.clearRect(0, 0, width, height);

  const total = appData.identities.length;
  const low = appData.identities.filter(i => i.risk_level === 'Low').length;
  const med = appData.identities.filter(i => i.risk_level === 'Medium').length;
  const high = appData.identities.filter(i => i.risk_level === 'High').length;

  const data = [
    { label: 'Low', count: low, color: '#10b981', glow: 'rgba(16, 185, 129, 0.4)' },
    { label: 'Medium', count: med, color: '#f59e0b', glow: 'rgba(245, 158, 11, 0.4)' },
    { label: 'High', count: high, color: '#ff3366', glow: 'rgba(255, 51, 102, 0.4)' }
  ];

  const centerX = width / 2;
  const centerY = height / 2;
  const radius = Math.min(centerX, centerY) - 20;
  const innerRadius = radius - 24;

  let startAngle = -Math.PI / 2;

  data.forEach(slice => {
    const sliceAngle = (slice.count / total) * 2 * Math.PI;
    const endAngle = startAngle + sliceAngle;

    ctx.save();
    ctx.shadowColor = slice.glow;
    ctx.shadowBlur = 10;
    ctx.beginPath();
    ctx.arc(centerX, centerY, radius, startAngle, endAngle);
    ctx.arc(centerX, centerY, innerRadius, endAngle, startAngle, true);
    ctx.closePath();
    ctx.fillStyle = slice.color;
    ctx.fill();
    ctx.restore();

    startAngle = endAngle;
  });

  // Center Text
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillStyle = '#ffffff';
  ctx.font = 'bold 26px "JetBrains Mono", monospace';
  ctx.fillText(total.toString(), centerX, centerY - 6);

  ctx.fillStyle = '#94a3b8';
  ctx.font = '10px "Inter", sans-serif';
  ctx.fillText('IDENTITIES', centerX, centerY + 18);
}

function drawHighRiskBarChart() {
  const canvas = document.getElementById('high-risk-bar-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const dpr = window.devicePixelRatio || 1;
  const width = canvas.clientWidth || 480;
  const height = canvas.clientHeight || 220;

  canvas.width = width * dpr;
  canvas.height = height * dpr;
  ctx.scale(dpr, dpr);

  ctx.clearRect(0, 0, width, height);

  const topRisks = appData.identities
    .filter(i => i.risk_level === 'High')
    .sort((a, b) => b.risk_score - a.risk_score)
    .slice(0, 6);

  if (topRisks.length === 0) {
    ctx.fillStyle = '#10b981';
    ctx.font = '14px "Inter", sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText('All high-risk identities have been remediated!', width / 2, height / 2);
    return;
  }

  const barHeight = 18;
  const gap = 14;
  const startY = 20;
  const labelWidth = 120;
  const maxBarWidth = width - labelWidth - 70;

  topRisks.forEach((item, idx) => {
    const y = startY + idx * (barHeight + gap);

    // Label
    ctx.fillStyle = '#f1f5f9';
    ctx.font = '500 12px "Inter", sans-serif';
    ctx.textAlign = 'right';
    ctx.fillText(item.name, labelWidth - 12, y + barHeight - 4);

    // Track Background
    ctx.fillStyle = 'rgba(255, 255, 255, 0.05)';
    ctx.beginPath();
    ctx.roundRect(labelWidth, y, maxBarWidth, barHeight, 4);
    ctx.fill();

    // Bar Fill
    const barWidth = (item.risk_score / 100) * maxBarWidth;
    const gradient = ctx.createLinearGradient(labelWidth, y, labelWidth + barWidth, y);
    gradient.addColorStop(0, '#f59e0b');
    gradient.addColorStop(1, '#ff3366');

    ctx.save();
    ctx.shadowColor = 'rgba(255, 51, 102, 0.35)';
    ctx.shadowBlur = 6;
    ctx.fillStyle = gradient;
    ctx.beginPath();
    ctx.roundRect(labelWidth, y, barWidth, barHeight, 4);
    ctx.fill();
    ctx.restore();

    // Score Value
    ctx.fillStyle = '#ff3366';
    ctx.font = 'bold 12px "JetBrains Mono", monospace';
    ctx.textAlign = 'left';
    ctx.fillText(`${item.risk_score}`, labelWidth + maxBarWidth + 12, y + barHeight - 4);
  });
}

/* ==========================================================================
   3. IDENTITY OVERVIEW TABLE
   ========================================================================== */
function renderIdentitiesTable() {
  const tbody = document.getElementById('identities-table-body');
  if (!tbody) return;

  tbody.innerHTML = '';
  const list = getFilteredIdentities();

  document.getElementById('identities-count-displayed').textContent = list.length;

  list.forEach(identity => {
    const tr = document.createElement('tr');

    const riskBadgeClass = identity.risk_level === 'High' ? 'badge-high' :
                           identity.risk_level === 'Medium' ? 'badge-medium' : 'badge-low';

    const avatarIcon = identity.type === 'User' ?
      `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>` :
      `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>`;

    tr.innerHTML = `
      <td>
        <div class="identity-name-cell">
          <div class="identity-avatar">
            ${avatarIcon}
          </div>
          <div class="identity-text">
            <strong>${identity.name}</strong>
            <span class="font-mono">${identity.arn}</span>
          </div>
        </div>
      </td>
      <td>
        <span class="badge ${identity.type === 'User' ? 'badge-cyan' : 'badge-purple'}">${identity.type}</span>
      </td>
      <td>
        <span class="font-mono" style="font-weight: 600;">${identity.permissions_count}</span>
      </td>
      <td>
        <span style="color: ${identity.last_used_days > 90 ? 'var(--risk-high)' : 'var(--text-secondary)'};">
          ${identity.last_used}
        </span>
      </td>
      <td>
        <span class="font-mono" style="font-weight: 700; color: ${identity.risk_level === 'High' ? 'var(--risk-high)' : identity.risk_level === 'Medium' ? 'var(--risk-medium)' : 'var(--risk-low)'};">
          ${identity.risk_score}/100
        </span>
      </td>
      <td>
        <span class="badge ${riskBadgeClass}">
          <span class="pulsing-dot"></span>
          ${identity.risk_level}
        </span>
      </td>
      <td style="text-align: right;">
        <button class="btn btn-secondary btn-sm" onclick="openAnalyzerForIdentity('${identity.name}')">
          View Details
        </button>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

function getFilteredIdentities() {
  const searchTerm = (document.getElementById('identity-search')?.value || '').toLowerCase().trim();
  const riskFilter = document.getElementById('filter-risk')?.value || 'All';
  const typeFilter = document.getElementById('filter-type')?.value || 'All';

  return appData.identities.filter(i => {
    const matchesSearch = i.name.toLowerCase().includes(searchTerm) || i.arn.toLowerCase().includes(searchTerm);
    const matchesRisk = riskFilter === 'All' || i.risk_level === riskFilter;
    const matchesType = typeFilter === 'All' || i.type === typeFilter;
    return matchesSearch && matchesRisk && matchesType;
  });
}

function filterIdentitiesTable() {
  renderIdentitiesTable();
}

function exportIdentitiesCSV() {
  const headers = ['Identity', 'Type', 'ARN', 'PermissionsCount', 'LastUsed', 'RiskScore', 'RiskLevel', 'Status'];
  const rows = appData.identities.map(i => [
    i.name, i.type, i.arn, i.permissions_count, `"${i.last_used}"`, i.risk_score, i.risk_level, i.status
  ]);

  let csvContent = 'data:text/csv;charset=utf-8,' + headers.join(',') + '\n' + rows.map(e => e.join(',')).join('\n');
  const encodedUri = encodeURI(csvContent);
  const link = document.createElement('a');
  link.setAttribute('href', encodedUri);
  link.setAttribute('download', 'trustnox_identities_report.csv');
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);

  showToast('Identities inventory exported as CSV.', 'success');
}

/* ==========================================================================
   4. & 5. PERMISSION ANALYZER & RISK SCORING
   ========================================================================== */
function populateAnalyzerDropdown() {
  const select = document.getElementById('analyzer-identity-select');
  if (!select) return;

  select.innerHTML = '';
  appData.identities.forEach(i => {
    const opt = document.createElement('option');
    opt.value = i.name;
    opt.textContent = `${i.name} (${i.risk_level} Risk — ${i.risk_score}/100)`;
    if (i.name === selectedIdentityId) {
      opt.selected = true;
    }
    select.appendChild(opt);
  });
}

function openAnalyzerForIdentity(identityName) {
  selectedIdentityId = identityName;
  const select = document.getElementById('analyzer-identity-select');
  if (select) select.value = identityName;
  loadAnalyzerData(identityName);
  switchTab('analyzer');
}

function loadAnalyzerData(identityName) {
  selectedIdentityId = identityName;
  const identity = appData.identities.find(i => i.name === identityName) || appData.identities[0];

  // Header Details
  document.getElementById('analyzer-target-name').textContent = identity.name;
  document.getElementById('analyzer-target-arn').textContent = identity.arn;
  document.getElementById('analyzer-type-badge').textContent = identity.type;

  const statusBadge = document.getElementById('analyzer-status-badge');
  statusBadge.textContent = identity.status;
  statusBadge.className = `badge ${identity.status === 'Active' ? 'badge-low' : 'badge-high'}`;

  // Risk Badge
  const riskBadgeBox = document.getElementById('analyzer-risk-badge-box');
  const riskClass = identity.risk_level === 'High' ? 'badge-high' :
                    identity.risk_level === 'Medium' ? 'badge-medium' : 'badge-low';
  riskBadgeBox.innerHTML = `<span class="badge ${riskClass}" style="font-size: 0.95rem; padding: 4px 14px;">Risk Level: ${identity.risk_level.toUpperCase()}</span>`;

  document.getElementById('analyzer-perm-count-badge').textContent = `${identity.permissions_count} Actions`;

  // Danger Banner
  const dangerReason = document.getElementById('analyzer-danger-reason');
  if (identity.risk_level === 'High') {
    dangerReason.textContent = '"Permissions exceed the expected access required for this identity."';
  } else if (identity.risk_level === 'Medium') {
    dangerReason.textContent = '"Broad actions detected; fine-grained resource constraints recommended."';
  } else {
    dangerReason.textContent = '"Access matches the role and conforms to least privilege baseline."';
  }

  // Permissions List
  const permsList = document.getElementById('analyzer-permissions-list');
  permsList.innerHTML = '';
  identity.permissions.forEach(p => {
    const item = document.createElement('div');
    item.className = `perm-item ${p.is_dangerous ? 'dangerous' : ''}`;
    item.innerHTML = `
      <div style="display: flex; align-items: center; gap: 10px;">
        <span class="perm-action-name">${p.action}</span>
        ${p.is_dangerous ? '<span class="badge badge-high" style="font-size: 0.65rem;">Dangerous</span>' : ''}
      </div>
      <div style="font-size: 0.78rem; color: var(--text-muted); max-width: 50%; text-align: right;">
        ${p.reason}
      </div>
    `;
    permsList.appendChild(item);
  });

  // Risk Meter & Score
  const scoreVal = identity.risk_score;
  document.getElementById('score-meter-val').textContent = scoreVal;
  document.getElementById('score-meter-val').style.color =
    identity.risk_level === 'High' ? 'var(--risk-high)' :
    identity.risk_level === 'Medium' ? 'var(--risk-medium)' : 'var(--risk-low)';

  const circle = document.getElementById('score-meter-circle');
  circle.setAttribute('stroke',
    identity.risk_level === 'High' ? 'var(--risk-high)' :
    identity.risk_level === 'Medium' ? 'var(--risk-medium)' : 'var(--risk-low)');

  // SVG dash calculation: perimeter = 2 * PI * 40 = 251.2
  const offset = 251.2 - (scoreVal / 100) * 251.2;
  circle.style.strokeDashoffset = offset.toString();

  document.getElementById('score-level-headline').textContent =
    `Risk Score: ${scoreVal}/100 — ${identity.risk_level.toUpperCase()}`;
  document.getElementById('score-level-headline').style.color =
    identity.risk_level === 'High' ? 'var(--risk-high)' :
    identity.risk_level === 'Medium' ? 'var(--risk-medium)' : 'var(--risk-low)';

  // Contributing Reasons List
  const reasonsList = document.getElementById('analyzer-risk-reasons-list');
  reasonsList.innerHTML = '';
  identity.risk_reasons.forEach(r => {
    const div = document.createElement('div');
    div.className = 'score-contrib-item';
    div.innerHTML = `
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="${identity.risk_level === 'High' ? 'var(--risk-high)' : 'var(--cyber-cyan)'}" stroke-width="2">
        <polyline points="20 6 9 17 4 12"/>
      </svg>
      <span>${r}</span>
    `;
    reasonsList.appendChild(div);
  });

  // Raw JSON Policy Document
  renderRawPolicyDocument(identity.name);
}

function renderRawPolicyDocument(identityName) {
  const codeBox = document.getElementById('analyzer-policy-code');
  const policyObj = appData.policy_raw_examples[identityName] || {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": appData.identities.find(i => i.name === identityName)?.permissions.map(p => p.action) || ["*"],
        "Resource": "*"
      }
    ]
  };

  const rawJson = JSON.stringify(policyObj, null, 2);

  // Syntax highlighting
  const highlighted = rawJson
    .replace(/"(.*?)":/g, '<span class="syntax-key">"$1"</span>:')
    .replace(/: "(.*?)"/g, ': <span class="syntax-string">"$1"</span>')
    .replace(/"(iam:PassRole|sts:AssumeRole|\*)"/g, '<span class="syntax-danger">"$1"</span>')
    .replace(/"Comment": "(.*?)"/g, '<span class="syntax-comment">"Comment": "$1"</span>');

  codeBox.innerHTML = `<pre><code>${highlighted}</code></pre>`;
}

function jumpToEscalationGraph() {
  switchTab('graph');
}

/* ==========================================================================
   6. PRIVILEGE ESCALATION GRAPH (INTERACTIVE SVG ENGINE)
   ========================================================================== */
function changeEscalationScenario(scenarioId) {
  activeEscalationScenario = scenarioId;
  renderEscalationGraph(scenarioId);
}

function renderEscalationGraph(scenarioId) {
  const svg = document.getElementById('escalation-graph-svg');
  if (!svg) return;

  svg.innerHTML = '';
  const chain = appData.escalation_chains.find(c => c.id === scenarioId) || appData.escalation_chains[0];

  // SVG Definitions: Markers, Gradients, Filters
  const defs = document.createElementNS('http://www.w3.org/2000/svg', 'defs');
  defs.innerHTML = `
    <!-- Glowing Red Flow Line Gradient -->
    <linearGradient id="edgeGlow" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" stop-color="#ff3366" stop-opacity="0.8"/>
      <stop offset="50%" stop-color="#00f0ff" stop-opacity="0.9"/>
      <stop offset="100%" stop-color="#ff3366" stop-opacity="1"/>
    </linearGradient>

    <!-- Arrowhead Marker -->
    <marker id="arrow" viewBox="0 0 10 10" refX="28" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M 0 1 L 10 5 L 0 9 z" fill="#ff3366" />
    </marker>

    <!-- Node Glow Filter -->
    <filter id="glow-filter" x="-20%" y="-20%" width="140%" height="140%">
      <feGaussianBlur stdDeviation="6" result="blur" />
      <feComposite in="SourceGraphic" in2="blur" operator="over" />
    </filter>
  `;
  svg.appendChild(defs);

  const containerWidth = svg.clientWidth || 1100;
  const containerHeight = svg.clientHeight || 520;

  // Responsive position layout
  const nodeCount = chain.nodes.length;
  const paddingX = 90;
  const availableWidth = containerWidth - (paddingX * 2);
  const stepX = availableWidth / (nodeCount - 1);
  const centerY = containerHeight / 2;

  // Update node coordinates dynamically for container sizing
  chain.nodes.forEach((node, i) => {
    node.currentX = paddingX + i * stepX;
    // Slight wave offset for visual dynamics
    node.currentY = centerY + (i % 2 === 0 ? -30 : 30);
  });

  // Render Edges
  chain.edges.forEach(edge => {
    const sourceNode = chain.nodes.find(n => n.id === edge.from);
    const targetNode = chain.nodes.find(n => n.id === edge.to);

    if (sourceNode && targetNode) {
      const gEdge = document.createElementNS('http://www.w3.org/2000/svg', 'g');
      gEdge.style.cursor = 'pointer';

      // Curved Path
      const dx = targetNode.currentX - sourceNode.currentX;
      const dy = targetNode.currentY - sourceNode.currentY;
      const cx1 = sourceNode.currentX + dx * 0.5;
      const cy1 = sourceNode.currentY;
      const cx2 = sourceNode.currentX + dx * 0.5;
      const cy2 = targetNode.currentY;

      const pathData = `M ${sourceNode.currentX} ${sourceNode.currentY} C ${cx1} ${cy1}, ${cx2} ${cy2}, ${targetNode.currentX} ${targetNode.currentY}`;

      // Outer glow line
      const glowLine = document.createElementNS('http://www.w3.org/2000/svg', 'path');
      glowLine.setAttribute('d', pathData);
      glowLine.setAttribute('stroke', 'rgba(255, 51, 102, 0.4)');
      glowLine.setAttribute('stroke-width', '8');
      glowLine.setAttribute('fill', 'none');
      gEdge.appendChild(glowLine);

      // Core pulsating path
      const mainLine = document.createElementNS('http://www.w3.org/2000/svg', 'path');
      mainLine.setAttribute('d', pathData);
      mainLine.setAttribute('stroke', '#ff3366');
      mainLine.setAttribute('stroke-width', '3');
      mainLine.setAttribute('stroke-dasharray', '8 4');
      mainLine.setAttribute('fill', 'none');
      mainLine.setAttribute('marker-end', 'url(#arrow)');

      // Animate flowing dashes
      const anim = document.createElementNS('http://www.w3.org/2000/svg', 'animate');
      anim.setAttribute('attributeName', 'stroke-dashoffset');
      anim.setAttribute('from', '40');
      anim.setAttribute('to', '0');
      anim.setAttribute('dur', '1.2s');
      anim.setAttribute('repeatCount', 'indefinite');
      mainLine.appendChild(anim);
      gEdge.appendChild(mainLine);

      // Edge Label
      if (edge.label) {
        const textLabel = document.createElementNS('http://www.w3.org/2000/svg', 'text');
        textLabel.setAttribute('x', (sourceNode.currentX + targetNode.currentX) / 2);
        textLabel.setAttribute('y', (sourceNode.currentY + targetNode.currentY) / 2 - 12);
        textLabel.setAttribute('fill', '#00f0ff');
        textLabel.setAttribute('font-size', '10');
        textLabel.setAttribute('font-family', 'JetBrains Mono, monospace');
        textLabel.setAttribute('text-anchor', 'middle');
        textLabel.textContent = edge.label;
        gEdge.appendChild(textLabel);
      }

      svg.appendChild(gEdge);
    }
  });

  // Render Nodes
  chain.nodes.forEach(node => {
    const gNode = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    gNode.setAttribute('transform', `translate(${node.currentX}, ${node.currentY})`);
    gNode.style.cursor = 'pointer';

    gNode.onclick = () => {
      inspectGraphNode(node);
    };

    // Node Glow Halo
    const halo = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    halo.setAttribute('r', '28');
    halo.setAttribute('fill', node.risk === 'Critical' || node.risk === 'High' ? 'rgba(255, 51, 102, 0.15)' : 'rgba(0, 240, 255, 0.15)');
    halo.setAttribute('stroke', node.risk === 'Critical' || node.risk === 'High' ? '#ff3366' : '#00f0ff');
    halo.setAttribute('stroke-width', '1.5');
    gNode.appendChild(halo);

    // Inner Circle
    const inner = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    inner.setAttribute('r', '16');
    inner.setAttribute('fill', '#0d131f');
    inner.setAttribute('stroke', node.risk === 'Critical' || node.risk === 'High' ? '#ff3366' : '#00f0ff');
    inner.setAttribute('stroke-width', '2');
    gNode.appendChild(inner);

    // Center Pulse Dot
    const dot = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    dot.setAttribute('r', '5');
    dot.setAttribute('fill', node.risk === 'Critical' || node.risk === 'High' ? '#ff3366' : '#00f0ff');
    gNode.appendChild(dot);

    // Label Text
    const label = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    label.setAttribute('y', '46');
    label.setAttribute('fill', '#ffffff');
    label.setAttribute('font-size', '12');
    label.setAttribute('font-weight', '600');
    label.setAttribute('font-family', 'Inter, sans-serif');
    label.setAttribute('text-anchor', 'middle');
    label.textContent = node.label;
    gNode.appendChild(label);

    // Subtype tag
    const sub = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    sub.setAttribute('y', '60');
    sub.setAttribute('fill', '#94a3b8');
    sub.setAttribute('font-size', '9');
    sub.setAttribute('font-family', 'JetBrains Mono, monospace');
    sub.setAttribute('text-anchor', 'middle');
    sub.textContent = node.type.toUpperCase();
    gNode.appendChild(sub);

    svg.appendChild(gNode);
  });
}

function inspectGraphNode(node) {
  document.getElementById('inspector-node-title').textContent = node.label;
  const badge = document.getElementById('inspector-node-badge');
  badge.textContent = `${node.risk} Risk`;
  badge.className = `badge ${node.risk === 'Critical' || node.risk === 'High' ? 'badge-high' : 'badge-medium'}`;

  document.getElementById('inspector-node-desc').textContent =
    `${node.desc}. Role category: ${node.role_type}. Connected in privilege chain.`;
}

function resetGraphView() {
  renderEscalationGraph(activeEscalationScenario);
  showToast('Graph visualization centered.', 'info');
}

/* ==========================================================================
   7. UNUSED ACCOUNT FINDER
   ========================================================================== */
function renderUnusedAccountsTable() {
  const tbody = document.getElementById('unused-table-body');
  if (!tbody) return;

  tbody.innerHTML = '';
  const unusedList = appData.identities.filter(i => i.is_unused);

  unusedList.forEach(item => {
    const tr = document.createElement('tr');
    const isAlreadyDisabled = item.status === 'Disabled';

    tr.innerHTML = `
      <td>
        <div style="display: flex; align-items: center; gap: 10px;">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--risk-high)" stroke-width="2"><path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><line x1="18" y1="8" x2="23" y2="13"/><line x1="23" y1="8" x2="18" y2="13"/></svg>
          <div>
            <strong style="color: ${isAlreadyDisabled ? 'var(--text-muted)' : '#fff'}; text-decoration: ${isAlreadyDisabled ? 'line-through' : 'none'};">${item.name}</strong>
            <div class="font-mono" style="font-size: 0.75rem; color: var(--text-muted);">${item.arn}</div>
          </div>
        </div>
      </td>
      <td>
        <span class="badge ${item.type === 'User' ? 'badge-cyan' : 'badge-purple'}">${item.type}</span>
      </td>
      <td>
        <span class="font-mono" style="font-weight: 600;">${item.permissions_count} active APIs</span>
      </td>
      <td>
        <span style="color: var(--risk-high); font-weight: 600;">${item.last_used}</span>
      </td>
      <td>
        <span class="badge ${item.risk_level === 'High' ? 'badge-high' : 'badge-medium'}">${item.risk_level}</span>
      </td>
      <td>
        <span class="badge ${isAlreadyDisabled ? 'badge-medium' : 'badge-high'}">
          ${item.status}
        </span>
      </td>
      <td style="text-align: right;">
        <button class="btn ${isAlreadyDisabled ? 'btn-secondary' : 'btn-danger'} btn-sm" 
          ${isAlreadyDisabled ? 'disabled style="opacity: 0.5; cursor: not-allowed;"' : ''} 
          onclick="disableAccount('${item.name}')">
          ${isAlreadyDisabled ? 'Account Disabled' : 'Disable Account'}
        </button>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

function disableAccount(accountName) {
  const target = appData.identities.find(i => i.name === accountName);
  if (target) {
    target.status = 'Disabled';
    target.risk_score = 15;
    target.risk_level = 'Low';

    renderUnusedAccountsTable();
    renderDashboardKPIs();
    renderIdentitiesTable();
    drawDonutChart();
    drawHighRiskBarChart();

    showToast(`Account "${accountName}" has been successfully disabled and keys revoked.`, 'success');
  }
}

function bulkDisableUnusedAccounts() {
  appData.identities.forEach(i => {
    if (i.is_unused) {
      i.status = 'Disabled';
      i.risk_score = 15;
      i.risk_level = 'Low';
    }
  });

  renderUnusedAccountsTable();
  renderDashboardKPIs();
  renderIdentitiesTable();
  drawDonutChart();
  drawHighRiskBarChart();

  showToast('All 4 dormant cloud accounts disabled. Inactive attack surface eliminated.', 'success');
}

/* ==========================================================================
   8. RISK REPORTS (RANKED LIST & EXPORT)
   ========================================================================== */
function renderRankedReportsTable(filter) {
  const tbody = document.getElementById('ranked-reports-body');
  if (!tbody) return;

  // Update filter buttons
  document.querySelectorAll('.report-filter-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.filter === filter);
  });

  tbody.innerHTML = '';
  let list = [...appData.identities].sort((a, b) => b.risk_score - a.risk_score);

  if (filter !== 'All') {
    list = list.filter(i => i.risk_level === filter);
  }

  list.forEach((identity, index) => {
    const tr = document.createElement('tr');
    const riskBadgeClass = identity.risk_level === 'High' ? 'badge-high' :
                           identity.risk_level === 'Medium' ? 'badge-medium' : 'badge-low';

    tr.innerHTML = `
      <td class="font-mono" style="font-weight: 700; color: var(--text-muted); font-size: 1.05rem;">
        #${index + 1}
      </td>
      <td>
        <strong style="color: #fff;">${identity.name}</strong>
        <div class="font-mono" style="font-size: 0.75rem; color: var(--text-muted);">${identity.arn}</div>
      </td>
      <td>
        <span class="badge ${identity.type === 'User' ? 'badge-cyan' : 'badge-purple'}">${identity.type}</span>
      </td>
      <td>
        <span class="font-mono" style="font-weight: 700; font-size: 1.05rem; color: ${identity.risk_level === 'High' ? 'var(--risk-high)' : identity.risk_level === 'Medium' ? 'var(--risk-medium)' : 'var(--risk-low)'};">
          ${identity.risk_score}/100
        </span>
      </td>
      <td>
        <span class="badge ${riskBadgeClass}">${identity.risk_level}</span>
      </td>
      <td style="font-size: 0.82rem; color: var(--text-secondary); max-width: 320px;">
        ${identity.risk_reasons[0] || 'Standard compliant permissions.'}
      </td>
      <td style="text-align: right;">
        <button class="btn btn-secondary btn-sm" onclick="openAnalyzerForIdentity('${identity.name}')">
          Analyze
        </button>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

function filterReportsTable(filter) {
  renderRankedReportsTable(filter);
}

function generateExecutiveReport() {
  const modal = document.getElementById('modal-report');
  const content = document.getElementById('executive-report-content');

  const high = appData.identities.filter(i => i.risk_level === 'High').length;
  const med = appData.identities.filter(i => i.risk_level === 'Medium').length;
  const low = appData.identities.filter(i => i.risk_level === 'Low').length;

  content.innerHTML = `
    <div style="background: rgba(255,255,255,0.02); padding: 18px; border-radius: var(--radius-md); border: 1px solid var(--border-subtle); margin-bottom: 20px;">
      <h4 style="color: var(--cyber-cyan); font-size: 1rem; margin-bottom: 8px;">Executive Summary & Posture Grade</h4>
      <p style="font-size: 0.88rem; color: var(--text-secondary);">
        Trustnox completed an evaluation of AWS IAM account <code>892147365012</code>. 
        Total Identities evaluated: <strong>25</strong>. 
        High Risk: <strong style="color: var(--risk-high);">${high}</strong>, 
        Medium Risk: <strong style="color: var(--risk-medium);">${med}</strong>, 
        Low Risk: <strong style="color: var(--risk-low);">${low}</strong>.
      </p>
      <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-top: 14px;">
        <div style="padding: 10px; background: rgba(0,0,0,0.3); border-radius: 6px;">
          <div style="font-size: 0.75rem; color: var(--text-muted);">CIS Benchmark 1.16</div>
          <strong style="color: ${high > 0 ? 'var(--risk-high)' : 'var(--risk-low)'};">${high > 0 ? 'FAIL (Wildcards Found)' : 'PASS'}</strong>
        </div>
        <div style="padding: 10px; background: rgba(0,0,0,0.3); border-radius: 6px;">
          <div style="font-size: 0.75rem; color: var(--text-muted);">Dormant Key Hygiene</div>
          <strong style="color: var(--risk-high);">4 Accounts >90 Days</strong>
        </div>
        <div style="padding: 10px; background: rgba(0,0,0,0.3); border-radius: 6px;">
          <div style="font-size: 0.75rem; color: var(--text-muted);">Escalation Vectors</div>
          <strong style="color: var(--risk-high);">3 Active Chains</strong>
        </div>
      </div>
    </div>

    <h4 style="font-size: 0.95rem; margin-bottom: 12px;">Top Ranked High-Risk Cloud Identities:</h4>
    <div style="display: flex; flex-direction: column; gap: 8px;">
      ${appData.identities.filter(i => i.risk_level === 'High').map((item, idx) => `
        <div style="display: flex; align-items: center; justify-content: space-between; padding: 10px 14px; background: rgba(255, 51, 102, 0.05); border: 1px solid rgba(255, 51, 102, 0.2); border-radius: 6px;">
          <div>
            <strong>${idx + 1}. ${item.name}</strong> (${item.type})
            <div style="font-size: 0.76rem; color: var(--text-secondary);">${item.remediation.fix}</div>
          </div>
          <span class="font-mono" style="color: var(--risk-high); font-weight: 700;">Score: ${item.risk_score}</span>
        </div>
      `).join('')}
    </div>
  `;

  modal.classList.add('active');
}

function closeReportModal() {
  document.getElementById('modal-report').classList.remove('active');
}

function downloadJSONReport() {
  const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(appData, null, 2));
  const downloadAnchor = document.createElement('a');
  downloadAnchor.setAttribute("href", dataStr);
  downloadAnchor.setAttribute("download", "trustnox_audit_report.json");
  document.body.appendChild(downloadAnchor);
  downloadAnchor.click();
  downloadAnchor.remove();
  showToast('JSON Risk Audit Report downloaded.', 'success');
}

/* ==========================================================================
   9. LEAST-PRIVILEGE RECOMMENDATIONS (RECOMMENDED FIXES)
   ========================================================================== */
function renderRecommendationsList() {
  const container = document.getElementById('recommendations-container');
  if (!container) return;

  container.innerHTML = '';

  // Filter identities that have actionable fixes
  const actionable = appData.identities.filter(i => i.remediation && i.remediation.problem !== 'None');

  actionable.forEach(item => {
    const card = document.createElement('div');
    const isRemediated = item.is_remediated === true;

    card.className = `recom-card glass-panel ${item.risk_level === 'Medium' ? 'med-border' : ''} ${isRemediated ? 'remediated' : ''}`;

    card.innerHTML = `
      <div class="recom-main">
        <div class="recom-header-row">
          <span class="recom-identity-title">${item.name}</span>
          <span class="badge ${item.risk_level === 'High' ? 'badge-high' : 'badge-medium'}">
            Risk: ${item.risk_level} (${item.risk_score}/100)
          </span>
          ${isRemediated ? '<span class="badge badge-low">Remediated</span>' : ''}
        </div>

        <div class="recom-problem-box">
          <strong>Problem:</strong>
          <p>${item.remediation.problem}</p>
        </div>

        <div class="recom-fix-box">
          <strong>Recommended Fix:</strong>
          <p>${item.remediation.fix}</p>
        </div>
      </div>

      <div>
        <button class="btn ${isRemediated ? 'btn-secondary' : 'btn-primary'}" 
          onclick="openRemediationModal('${item.name}')">
          ${isRemediated ? 'View Policy Diff' : 'Apply Fix'}
        </button>
      </div>
    `;

    container.appendChild(card);
  });
}

function openRemediationModal(identityName) {
  currentRemediationTarget = identityName;
  const identity = appData.identities.find(i => i.name === identityName);
  if (!identity) return;

  document.getElementById('remed-modal-title').textContent = `Least-Privilege Remediation: ${identity.name}`;
  document.getElementById('remed-modal-desc').textContent = identity.remediation.fix;

  const diffBox = document.getElementById('remed-diff-code');
  diffBox.innerHTML = `<pre><code>${escapeHtml(identity.remediation.policy_diff)}</code></pre>`;

  const btnConfirm = document.getElementById('btn-confirm-apply-fix');
  if (identity.is_remediated) {
    btnConfirm.textContent = 'Rollback Policy';
    btnConfirm.className = 'btn btn-secondary btn-sm';
  } else {
    btnConfirm.textContent = 'Confirm & Enforce Least-Privilege';
    btnConfirm.className = 'btn btn-primary btn-sm';
  }

  document.getElementById('modal-remediation').classList.add('active');
}

function closeRemediationModal() {
  document.getElementById('modal-remediation').classList.remove('active');
}

function executeRemediation() {
  if (!currentRemediationTarget) return;

  const identity = appData.identities.find(i => i.name === currentRemediationTarget);
  if (!identity) return;

  if (identity.is_remediated) {
    // Rollback
    identity.is_remediated = false;
    identity.risk_score = identity.original_score || 85;
    identity.risk_level = 'High';
    showToast(`Remediation rolled back for ${identity.name}.`, 'info');
  } else {
    // Apply Fix
    identity.original_score = identity.risk_score;
    identity.is_remediated = true;
    identity.risk_score = 25;
    identity.risk_level = 'Low';
    identity.in_escalation_path = false;

    showToast(`Least-privilege policy successfully enforced on ${identity.name}!`, 'success');
  }

  closeRemediationModal();
  renderRecommendationsList();
  renderDashboardKPIs();
  renderIdentitiesTable();
  drawDonutChart();
  drawHighRiskBarChart();
}

function applyRemediation(identityName) {
  openRemediationModal(identityName);
}

function applyAllRecommendations() {
  appData.identities.forEach(i => {
    if (i.remediation && i.remediation.problem !== 'None') {
      i.is_remediated = true;
      i.original_score = i.risk_score;
      i.risk_score = 22;
      i.risk_level = 'Low';
      i.in_escalation_path = false;
    }
  });

  renderRecommendationsList();
  renderDashboardKPIs();
  renderIdentitiesTable();
  drawDonutChart();
  drawHighRiskBarChart();

  showToast('All recommended least-privilege policies applied! Cloud security score improved.', 'success');
}

/* ==========================================================================
   11. SCAN / ANALYZE FEATURE (SIMULATED 7-STAGE PIPELINE)
   ========================================================================== */
function triggerScanModal() {
  const modal = document.getElementById('modal-scan');
  modal.classList.add('active');

  const fill = document.getElementById('scan-progress-fill');
  fill.style.width = '0%';
  document.getElementById('scan-completed-box').style.display = 'none';
  document.getElementById('btn-scan-view-findings').style.display = 'none';
  document.getElementById('scan-modal-status-badge').textContent = 'Processing...';

  // Reset steps
  const steps = [1, 2, 3, 4, 5, 6, 7];
  steps.forEach(s => {
    const el = document.getElementById(`scan-step-${s}`);
    el.className = 'scan-step-item';
  });

  let currentStep = 1;
  if (scanInterval) clearInterval(scanInterval);

  scanInterval = setInterval(() => {
    if (currentStep <= 7) {
      // Mark active
      const activeEl = document.getElementById(`scan-step-${currentStep}`);
      activeEl.className = 'scan-step-item active';

      if (currentStep > 1) {
        const prevEl = document.getElementById(`scan-step-${currentStep - 1}`);
        prevEl.className = 'scan-step-item completed';
        prevEl.innerHTML = `
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
          <span class="font-mono">0${currentStep - 1}</span> ${getStepTitle(currentStep - 1)}
        `;
      }

      const progressPercent = Math.round((currentStep / 7) * 100);
      fill.style.width = `${progressPercent}%`;

      currentStep++;
    } else {
      // Completed Step 7
      clearInterval(scanInterval);
      const lastEl = document.getElementById(`scan-step-7`);
      lastEl.className = 'scan-step-item completed';
      lastEl.innerHTML = `
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
        <span class="font-mono">07</span> Generate recommendations
      `;

      fill.style.width = '100%';
      document.getElementById('scan-modal-status-badge').textContent = 'COMPLETED';
      document.getElementById('scan-modal-status-badge').className = 'badge badge-low';
      document.getElementById('scan-completed-box').style.display = 'block';
      document.getElementById('btn-scan-view-findings').style.display = 'inline-flex';

      showToast('IAM Security Scan Completed. 6 High Risk identities detected.', 'danger');
    }
  }, 450);
}

function getStepTitle(idx) {
  const titles = [
    '',
    'Ingest IAM data',
    'Parse users, roles and policies',
    'Map permissions and trust relationships',
    'Analyze risky patterns',
    'Calculate risk scores',
    'Detect escalation paths',
    'Generate recommendations'
  ];
  return titles[idx] || '';
}

function closeScanModal() {
  if (scanInterval) clearInterval(scanInterval);
  document.getElementById('modal-scan').classList.remove('active');
}

function finishScanAndReview() {
  closeScanModal();
  switchTab('identities', 'High');
}

/* ==========================================================================
   12. BACKEND ENGINE CLI DEMO
   ========================================================================== */
function runBackendAnalysisDemo() {
  showToast('Executing Python NetworkX Analysis Engine (py trustnox_engine.py)...', 'info');
  setTimeout(() => {
    showToast('Python Engine output: 25 identities processed, 3 escalation paths verified via DiGraph.', 'success');
  }, 1000);
}

/* ==========================================================================
   TOAST SYSTEM & HELPERS
   ========================================================================== */
function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;

  const icon = type === 'success' ?
    `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--risk-low)" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>` :
    type === 'danger' ?
    `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--risk-high)" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>` :
    `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--cyber-cyan)" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>`;

  toast.innerHTML = `
    ${icon}
    <span>${message}</span>
  `;

  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(100%)';
    toast.style.transition = 'all 0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, 4200);
}

function escapeHtml(string) {
  return String(string)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
