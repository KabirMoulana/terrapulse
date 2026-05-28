# TerraPulse - Infrastructure Drift & Compliance Policies
# Written in OPA Rego — evaluated by the policy-engine service for every resource snapshot.
#
# Policy structure:
#   violations[v]  — resources that violate a policy (will trigger drift alert)
#   remediations[r] — auto-remediation actions for approved violation types
#
# All policies are unit-tested in policies/tests/

package terrapulse.policies

import future.keywords.if
import future.keywords.in
import future.keywords.every

# ── Metadata ──────────────────────────────────────────────────────────────────

policy_version := "1.4.0"

# ── Security Group Policies ───────────────────────────────────────────────────

# CRITICAL: Security group must not allow 0.0.0.0/0 ingress on sensitive ports
violations[v] if {
    resource := input.resources[_]
    resource.type == "aws::ec2::SecurityGroup"

    # Check each ingress rule
    rule := resource.state.IpPermissions[_]
    range := rule.IpRanges[_]
    range.CidrIp == "0.0.0.0/0"

    # Sensitive ports that must never be open to the world
    sensitive_ports := {22, 3306, 5432, 6379, 27017, 9200, 8080, 8443}
    rule.FromPort <= port
    rule.ToPort >= port
    port := sensitive_ports[_]

    v := {
        "id":          sprintf("sg-open-world-%v-%v", [resource.id, port]),
        "resource_id": resource.id,
        "resource_type": resource.type,
        "policy":      "no-world-ingress-sensitive-ports",
        "severity":    "CRITICAL",
        "title":       sprintf("Security group %v allows 0.0.0.0/0 on port %v", [resource.name, port]),
        "description": sprintf(
            "Security group '%v' (%v) has an ingress rule allowing unrestricted access (0.0.0.0/0) on port %v. This is a critical security risk.",
            [resource.name, resource.id, port]
        ),
        "remediation": "revoke-sg-ingress",
        "auto_remediate": false,  # Require human approval for security group changes
    }
}

# WARNING: Security group allows all traffic (port -1)
violations[v] if {
    resource := input.resources[_]
    resource.type == "aws::ec2::SecurityGroup"

    rule := resource.state.IpPermissions[_]
    rule.IpProtocol == "-1"  # All traffic
    range := rule.IpRanges[_]
    range.CidrIp == "0.0.0.0/0"

    v := {
        "id":           sprintf("sg-allow-all-%v", [resource.id]),
        "resource_id":  resource.id,
        "resource_type": resource.type,
        "policy":       "no-allow-all-ingress",
        "severity":     "CRITICAL",
        "title":        sprintf("Security group %v allows ALL traffic from 0.0.0.0/0", [resource.name]),
        "description":  "Security group has an allow-all rule. This exposes all ports to the internet.",
        "remediation":  "revoke-sg-all-ingress",
        "auto_remediate": false,
    }
}

# ── S3 Bucket Policies ────────────────────────────────────────────────────────

# CRITICAL: S3 bucket must not be public
violations[v] if {
    resource := input.resources[_]
    resource.type == "aws::s3::Bucket"

    # Check PublicAccessBlockConfiguration
    block_config := resource.state.PublicAccessBlockConfiguration
    not block_config.BlockPublicAcls == true

    v := {
        "id":           sprintf("s3-public-acl-%v", [resource.id]),
        "resource_id":  resource.id,
        "resource_type": resource.type,
        "policy":       "s3-block-public-acls",
        "severity":     "CRITICAL",
        "title":        sprintf("S3 bucket %v does not block public ACLs", [resource.name]),
        "description":  "S3 bucket is not configured to block public ACLs. Data may be publicly accessible.",
        "remediation":  "enable-s3-block-public-access",
        "auto_remediate": true,  # Safe to auto-remediate
    }
}

# HIGH: S3 bucket must have versioning enabled
violations[v] if {
    resource := input.resources[_]
    resource.type == "aws::s3::Bucket"

    # Skip buckets tagged as ephemeral/scratch
    not resource.tags["terrapulse:skip-versioning"] == "true"
    not resource.tags["Purpose"] == "scratch"

    versioning := resource.state.Versioning
    not versioning.Status == "Enabled"

    v := {
        "id":           sprintf("s3-no-versioning-%v", [resource.id]),
        "resource_id":  resource.id,
        "resource_type": resource.type,
        "policy":       "s3-versioning-required",
        "severity":     "HIGH",
        "title":        sprintf("S3 bucket %v does not have versioning enabled", [resource.name]),
        "description":  "Versioning protects against accidental deletion and overwrites. Enable it for data durability.",
        "remediation":  "enable-s3-versioning",
        "auto_remediate": true,
    }
}

# HIGH: S3 bucket must have server-side encryption enabled
violations[v] if {
    resource := input.resources[_]
    resource.type == "aws::s3::Bucket"

    encryption := resource.state.ServerSideEncryptionConfiguration
    not count(encryption.Rules) > 0

    v := {
        "id":           sprintf("s3-no-encryption-%v", [resource.id]),
        "resource_id":  resource.id,
        "resource_type": resource.type,
        "policy":       "s3-encryption-required",
        "severity":     "HIGH",
        "title":        sprintf("S3 bucket %v is not encrypted at rest", [resource.name]),
        "description":  "All S3 buckets must have SSE enabled. Use SSE-S3 at minimum, SSE-KMS for sensitive data.",
        "remediation":  "enable-s3-encryption",
        "auto_remediate": true,
    }
}

# ── Tagging Policies ──────────────────────────────────────────────────────────

# MEDIUM: Required tags must be present on all resources
required_tags := {"Environment", "Owner", "CostCenter", "ManagedBy"}

violations[v] if {
    resource := input.resources[_]
    resource.type in {"aws::ec2::Instance", "aws::rds::DBInstance", "aws::ec2::SecurityGroup"}

    tag := required_tags[_]
    not resource.tags[tag]

    v := {
        "id":           sprintf("missing-tag-%v-%v", [resource.id, tag]),
        "resource_id":  resource.id,
        "resource_type": resource.type,
        "policy":       "required-tags",
        "severity":     "MEDIUM",
        "title":        sprintf("Resource %v is missing required tag: %v", [resource.name, tag]),
        "description":  sprintf("Tag '%v' is required for cost allocation and ownership tracking.", [tag]),
        "remediation":  "add-required-tag",
        "auto_remediate": false,
        "metadata": {
            "missing_tag": tag,
        },
    }
}

# ── RDS Policies ──────────────────────────────────────────────────────────────

# CRITICAL: RDS instance must not be publicly accessible
violations[v] if {
    resource := input.resources[_]
    resource.type == "aws::rds::DBInstance"
    resource.state.PubliclyAccessible == true

    v := {
        "id":           sprintf("rds-public-%v", [resource.id]),
        "resource_id":  resource.id,
        "resource_type": resource.type,
        "policy":       "rds-not-public",
        "severity":     "CRITICAL",
        "title":        sprintf("RDS instance %v is publicly accessible", [resource.name]),
        "description":  "RDS instances must not be publicly accessible. Use a bastion host or VPN for access.",
        "remediation":  "disable-rds-public-access",
        "auto_remediate": false,
    }
}

# HIGH: RDS instance must have deletion protection enabled
violations[v] if {
    resource := input.resources[_]
    resource.type == "aws::rds::DBInstance"

    # Only enforce on prod instances
    resource.tags["Environment"] == "production"
    not resource.state.DeletionProtection == true

    v := {
        "id":           sprintf("rds-no-deletion-protection-%v", [resource.id]),
        "resource_id":  resource.id,
        "resource_type": resource.type,
        "policy":       "rds-deletion-protection",
        "severity":     "HIGH",
        "title":        sprintf("Production RDS instance %v lacks deletion protection", [resource.name]),
        "description":  "Deletion protection prevents accidental database deletion on production instances.",
        "remediation":  "enable-rds-deletion-protection",
        "auto_remediate": true,
    }
}

# ── Drift Detection ───────────────────────────────────────────────────────────

# A resource has drifted if its live state differs from its last known desired state.
# The desired state is provided by the control plane (sourced from Terraform state).
drift_detected[d] if {
    resource := input.resources[_]
    desired := input.desired_states[resource.id]

    # Check specific drift-sensitive fields based on resource type
    resource.type == "aws::ec2::SecurityGroup"
    live_rules := resource.state.IpPermissions
    desired_rules := desired.IpPermissions
    live_rules != desired_rules

    d := {
        "resource_id":   resource.id,
        "resource_type": resource.type,
        "drift_type":    "security_group_rules_changed",
        "live_state":    live_rules,
        "desired_state": desired_rules,
        "detected_at":   input.scan_timestamp,
    }
}

# ── Remediation Actions ───────────────────────────────────────────────────────

# For each auto-remediable violation, emit a remediation action.
# These are consumed by the control plane and dispatched to agents.
remediations[r] if {
    violation := violations[_]
    violation.auto_remediate == true

    r := {
        "violation_id":  violation.id,
        "resource_id":   violation.resource_id,
        "resource_type": violation.resource_type,
        "action":        violation.remediation,
        "parameters":    object.get(violation, "metadata", {}),
        "priority":      severity_to_priority(violation.severity),
    }
}

severity_to_priority(s) := 1 if s == "CRITICAL"
severity_to_priority(s) := 2 if s == "HIGH"
severity_to_priority(s) := 3 if s == "MEDIUM"
severity_to_priority(s) := 4 if s == "LOW"

# ── Summary ───────────────────────────────────────────────────────────────────

summary := {
    "total_resources":    count(input.resources),
    "total_violations":   count(violations),
    "critical_count":     count([v | v := violations[_]; v.severity == "CRITICAL"]),
    "high_count":         count([v | v := violations[_]; v.severity == "HIGH"]),
    "medium_count":       count([v | v := violations[_]; v.severity == "MEDIUM"]),
    "auto_remediable":    count([v | v := violations[_]; v.auto_remediate == true]),
    "drift_detected":     count(drift_detected),
    "policy_version":     policy_version,
    "evaluated_at":       input.scan_timestamp,
}
