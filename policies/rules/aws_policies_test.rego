# Unit tests for TerraPulse AWS policies
# Run with: opa test policies/ -v
package terrapulse.policies_test

import data.terrapulse.policies
import future.keywords.if

# ── Test helpers ──────────────────────────────────────────────────────────────

mock_sg_open_22 := {
    "id": "sg-12345678",
    "type": "aws::ec2::SecurityGroup",
    "name": "web-sg",
    "region": "us-east-1",
    "tags": {"Environment": "production", "Owner": "platform-team", "CostCenter": "eng", "ManagedBy": "terraform"},
    "state": {
        "GroupId": "sg-12345678",
        "GroupName": "web-sg",
        "IpPermissions": [
            {
                "FromPort": 22,
                "ToPort": 22,
                "IpProtocol": "tcp",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    },
}

mock_sg_restricted := {
    "id": "sg-99999999",
    "type": "aws::ec2::SecurityGroup",
    "name": "restricted-sg",
    "region": "us-east-1",
    "tags": {"Environment": "production", "Owner": "platform-team", "CostCenter": "eng", "ManagedBy": "terraform"},
    "state": {
        "GroupId": "sg-99999999",
        "GroupName": "restricted-sg",
        "IpPermissions": [
            {
                "FromPort": 443,
                "ToPort": 443,
                "IpProtocol": "tcp",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],  # HTTPS is OK
            }
        ],
    },
}

mock_s3_public := {
    "id": "my-public-bucket",
    "type": "aws::s3::Bucket",
    "name": "my-public-bucket",
    "region": "us-east-1",
    "tags": {},
    "state": {
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": false,
            "BlockPublicPolicy": false,
        },
        "Versioning": {"Status": "Suspended"},
    },
}

mock_s3_compliant := {
    "id": "my-private-bucket",
    "type": "aws::s3::Bucket",
    "name": "my-private-bucket",
    "region": "us-east-1",
    "tags": {},
    "state": {
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": true,
            "BlockPublicPolicy": true,
            "IgnorePublicAcls": true,
            "RestrictPublicBuckets": true,
        },
        "Versioning": {"Status": "Enabled"},
        "ServerSideEncryptionConfiguration": {
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}],
        },
    },
}

mock_rds_public := {
    "id": "mydb",
    "type": "aws::rds::DBInstance",
    "name": "mydb",
    "region": "us-east-1",
    "tags": {"Environment": "production", "Owner": "data-team", "CostCenter": "data", "ManagedBy": "terraform"},
    "state": {
        "DBInstanceIdentifier": "mydb",
        "PubliclyAccessible": true,
        "DeletionProtection": false,
    },
}

# ── Security Group Tests ──────────────────────────────────────────────────────

test_sg_open_port_22_is_violation if {
    input := {"resources": [mock_sg_open_22], "scan_timestamp": "2024-01-01T00:00:00Z"}
    violations := [v | v := policies.violations[_]; v.resource_id == "sg-12345678"]
    count(violations) > 0
    violations[0].severity == "CRITICAL"
    violations[0].policy == "no-world-ingress-sensitive-ports"
}

test_sg_https_only_is_not_violation if {
    input := {"resources": [mock_sg_restricted], "scan_timestamp": "2024-01-01T00:00:00Z"}
    violations := [v | v := policies.violations[_]; v.resource_id == "sg-99999999"; v.policy == "no-world-ingress-sensitive-ports"]
    count(violations) == 0
}

# ── S3 Tests ──────────────────────────────────────────────────────────────────

test_s3_public_bucket_is_violation if {
    input := {"resources": [mock_s3_public], "scan_timestamp": "2024-01-01T00:00:00Z"}
    violations := [v | v := policies.violations[_]; v.resource_id == "my-public-bucket"; v.policy == "s3-block-public-acls"]
    count(violations) == 1
    violations[0].auto_remediate == true  # S3 public access block is safe to auto-remediate
}

test_s3_compliant_bucket_has_no_violations if {
    input := {"resources": [mock_s3_compliant], "scan_timestamp": "2024-01-01T00:00:00Z", "desired_states": {}}
    violations := [v | v := policies.violations[_]; v.resource_id == "my-private-bucket"]
    count(violations) == 0
}

test_s3_public_bucket_generates_remediation if {
    input := {"resources": [mock_s3_public], "scan_timestamp": "2024-01-01T00:00:00Z"}
    remediations := [r | r := policies.remediations[_]; r.resource_id == "my-public-bucket"]
    count(remediations) > 0
}

# ── RDS Tests ─────────────────────────────────────────────────────────────────

test_rds_public_instance_is_critical_violation if {
    input := {"resources": [mock_rds_public], "scan_timestamp": "2024-01-01T00:00:00Z"}
    violations := [v | v := policies.violations[_]; v.resource_id == "mydb"; v.policy == "rds-not-public"]
    count(violations) == 1
    violations[0].severity == "CRITICAL"
    violations[0].auto_remediate == false  # RDS public access change requires approval
}

test_rds_prod_deletion_protection_violation if {
    input := {"resources": [mock_rds_public], "scan_timestamp": "2024-01-01T00:00:00Z"}
    violations := [v | v := policies.violations[_]; v.resource_id == "mydb"; v.policy == "rds-deletion-protection"]
    count(violations) == 1
    violations[0].auto_remediate == true
}

# ── Tagging Tests ─────────────────────────────────────────────────────────────

test_missing_tag_generates_medium_violation if {
    resource_no_owner := json.patch(mock_sg_open_22, [{"op": "remove", "path": "/tags/Owner"}])
    input := {"resources": [resource_no_owner], "scan_timestamp": "2024-01-01T00:00:00Z"}
    violations := [v | v := policies.violations[_]; v.policy == "required-tags"; contains(v.id, "Owner")]
    count(violations) == 1
    violations[0].severity == "MEDIUM"
}

# ── Summary Tests ─────────────────────────────────────────────────────────────

test_summary_counts_correctly if {
    input := {
        "resources": [mock_sg_open_22, mock_s3_public, mock_rds_public],
        "scan_timestamp": "2024-01-01T00:00:00Z",
        "desired_states": {},
    }
    summary := policies.summary
    summary.total_resources == 3
    summary.critical_count >= 2
}
