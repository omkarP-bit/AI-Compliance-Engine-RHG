package ace.cis.terraform

import future.keywords.if
import future.keywords.in

default allow := false

allow if count(deny) == 0

# CIS-TERRAFORM-1 — S3 bucket with public-read ACL
deny[finding] if {
    resource := input.metadata.resources[_]
    resource.type == "aws_s3_bucket"
    resource.values.acl == "public-read"
    finding := {
        "rule_id":   "CIS-TERRAFORM-1",
        "severity":  "CRITICAL",
        "message":   sprintf("S3 bucket '%v' has public-read ACL — data exposure risk", [resource.address]),
        "patchable": true,
        "reference": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html"
    }
}

# CIS-TERRAFORM-2 — S3 bucket missing encryption
deny[finding] if {
    resource := input.metadata.resources[_]
    resource.type == "aws_s3_bucket"
    not resource.values.server_side_encryption_configuration
    finding := {
        "rule_id":   "CIS-TERRAFORM-2",
        "severity":  "HIGH",
        "message":   sprintf("S3 bucket '%v' has no server-side encryption configured", [resource.address]),
        "patchable": true,
        "reference": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html"
    }
}

# CIS-TERRAFORM-3 — Security group with unrestricted ingress (0.0.0.0/0)
deny[finding] if {
    resource := input.metadata.resources[_]
    resource.type == "aws_security_group"
    ingress := resource.values.ingress
    is_array(ingress)
    rule := ingress[_]
    rule.cidr_blocks[_] == "0.0.0.0/0"
    finding := {
        "rule_id":   "CIS-TERRAFORM-3",
        "severity":  "CRITICAL",
        "message":   sprintf("Security group '%v' allows unrestricted ingress from 0.0.0.0/0", [resource.address]),
        "patchable": true,
        "reference": "https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html"
    }
}

# CIS-TERRAFORM-4 — Security group with unrestricted egress (0.0.0.0/0)
deny[finding] if {
    resource := input.metadata.resources[_]
    resource.type == "aws_security_group"
    egress := resource.values.egress
    is_array(egress)
    rule := egress[_]
    rule.cidr_blocks[_] == "0.0.0.0/0"
    rule.from_port == 0
    rule.to_port == 0
    rule.protocol == "-1"
    finding := {
        "rule_id":   "CIS-TERRAFORM-4",
        "severity":  "MEDIUM",
        "message":   sprintf("Security group '%v' allows unrestricted egress for all protocols", [resource.address]),
        "patchable": true,
        "reference": "https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html"
    }
}

# CIS-TERRAFORM-5 — EC2 instance with default security group
deny[finding] if {
    resource := input.metadata.resources[_]
    resource.type == "aws_instance"
    sg := resource.values.vpc_security_group_ids
    is_array(sg)
    some i
    contains(sg[i], "sg-")
    count(sg) == 1
    finding := {
        "rule_id":   "CIS-TERRAFORM-5",
        "severity":  "MEDIUM",
        "message":   sprintf("EC2 instance '%v' uses a single default-style security group — isolate with least-privilege rules", [resource.address]),
        "patchable": true,
        "reference": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-network-security.html"
    }
}

# CIS-TERRAFORM-6 — IAM policy with wildcard actions
deny[finding] if {
    resource := input.metadata.resources[_]
    resource.type == "aws_iam_policy"
    stmt := resource.values.policy
    is_string(stmt)
    contains(stmt, "\"Action\": \"*\"")
    finding := {
        "rule_id":   "CIS-TERRAFORM-6",
        "severity":  "HIGH",
        "message":   sprintf("IAM policy '%v' grants wildcard actions — principle of least privilege violated", [resource.address]),
        "patchable": false,
        "reference": "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege"
    }
}

# CIS-TERRAFORM-7 — RDS instance missing encryption at rest
deny[finding] if {
    resource := input.metadata.resources[_]
    resource.type in {"aws_db_instance", "aws_rds_cluster"}
    not resource.values.storage_encrypted
    finding := {
        "rule_id":   "CIS-TERRAFORM-7",
        "severity":  "HIGH",
        "message":   sprintf("Database instance '%v' has storage encryption disabled", [resource.address]),
        "patchable": false,
        "reference": "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.SSL.html"
    }
}

# Mutation patches
patch[op] if {
    resource := input.metadata.resources[_]
    resource.type == "aws_s3_bucket"
    resource.values.acl == "public-read"
    op := {
        "op":    "replace",
        "path":  sprintf("/metadata/resources/%d/values/acl", [resource._index]),
        "value": "private",
    }
}

patch[op] if {
    resource := input.metadata.resources[_]
    resource.type == "aws_s3_bucket"
    not resource.values.server_side_encryption_configuration
    op := {
        "op":    "add",
        "path":  sprintf("/metadata/resources/%d/values/server_side_encryption_configuration", [resource._index]),
        "value": {"rule": [{"apply_server_side_encryption_by_default": {"sse_algorithm": "AES256"}}]},
    }
}