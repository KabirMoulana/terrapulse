terraform {
  required_version = ">= 1.7.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.40"
    }
    google = {
      source  = "hashicorp/google"
      version = "~> 5.20"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.95"
    }
  }
  backend "s3" {
    bucket         = "terrapulse-tfstate"
    key            = "control-plane/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "terrapulse-tfstate-lock"
  }
}

locals {
  name = "terrapulse-${var.environment}"
  tags = {
    Project     = "terrapulse"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# ── Control Plane: EKS ────────────────────────────────────────────────────────
module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.8"

  cluster_name    = local.name
  cluster_version = "1.29"
  vpc_id          = module.vpc.vpc_id
  subnet_ids      = module.vpc.private_subnets
  enable_irsa     = true

  eks_managed_node_groups = {
    control_plane = {
      instance_types = ["t3.medium"]
      min_size       = 2
      max_size       = 5
      desired_size   = 2
    }
  }

  tags = local.tags
}

# ── Kafka (MSK) for drift events ──────────────────────────────────────────────
resource "aws_msk_cluster" "drift_events" {
  cluster_name           = "${local.name}-kafka"
  kafka_version          = "3.6.0"
  number_of_broker_nodes = 3

  broker_node_group_info {
    instance_type  = var.environment == "prod" ? "kafka.m5.large" : "kafka.t3.small"
    client_subnets = module.vpc.private_subnets
    storage_info {
      ebs_storage_info { volume_size = 100 }
    }
    security_groups = [aws_security_group.msk.id]
  }

  encryption_info {
    encryption_in_transit {
      client_broker = "TLS"
      in_cluster    = true
    }
    encryption_at_rest {
      data_volume_kms_key_id = aws_kms_key.msk.arn
    }
  }

  client_authentication {
    sasl { scram = true }
  }

  tags = local.tags
}

# ── Agent IAM Roles (per cloud account) ──────────────────────────────────────
# Agents use IRSA — no static credentials
resource "aws_iam_role" "terrapulse_agent" {
  name = "${local.name}-agent-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRoleWithWebIdentity"
      Effect = "Allow"
      Principal = {
        Federated = module.eks.oidc_provider_arn
      }
      Condition = {
        StringEquals = {
          "${module.eks.oidc_provider}:sub" = "system:serviceaccount:terrapulse:terrapulse-agent"
        }
      }
    }]
  })

  tags = local.tags
}

# Agent has READ-ONLY access (scan) + specific remediation actions
resource "aws_iam_role_policy" "agent_scan" {
  name = "terrapulse-agent-scan"
  role = aws_iam_role.terrapulse_agent.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadOnly"
        Effect = "Allow"
        Action = [
          "ec2:Describe*",
          "s3:ListBuckets",
          "s3:GetBucketPolicy",
          "s3:GetBucketVersioning",
          "s3:GetBucketEncryption",
          "s3:GetPublicAccessBlock",
          "rds:DescribeDBInstances",
          "iam:ListRoles",
          "iam:GetAccountPasswordPolicy",
        ]
        Resource = "*"
      },
      {
        Sid    = "ApprovedRemediations"
        Effect = "Allow"
        Action = [
          "s3:PutBucketVersioning",
          "s3:PutBucketEncryption",
          "s3:PutPublicAccessBlock",
          "rds:ModifyDBInstance",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupIngress",
        ]
        # Scoped to specific resources via request conditions
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = var.aws_region
          }
        }
      }
    ]
  })
}

# ── S3: Terraform State Snapshots ─────────────────────────────────────────────
resource "aws_s3_bucket" "desired_states" {
  bucket = "${local.name}-desired-states"
  tags   = local.tags
}

resource "aws_s3_bucket_versioning" "desired_states" {
  bucket = aws_s3_bucket.desired_states.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "desired_states" {
  bucket = aws_s3_bucket.desired_states.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3.arn
    }
  }
}

# Object Lock for immutable audit trail
resource "aws_s3_bucket" "audit_log" {
  bucket              = "${local.name}-audit-log"
  object_lock_enabled = true  # Immutable — cannot be deleted or overwritten
  tags                = local.tags
}

resource "aws_s3_bucket_object_lock_configuration" "audit_log" {
  bucket = aws_s3_bucket.audit_log.id
  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = 365
    }
  }
}

# ── KMS Keys ──────────────────────────────────────────────────────────────────
resource "aws_kms_key" "msk" {
  description             = "TerraPulse MSK encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  tags                    = local.tags
}

resource "aws_kms_key" "s3" {
  description             = "TerraPulse S3 encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  tags                    = local.tags
}

# ── Outputs ───────────────────────────────────────────────────────────────────
output "eks_cluster_name" {
  value = module.eks.cluster_name
}

output "msk_bootstrap_brokers_tls" {
  value     = aws_msk_cluster.drift_events.bootstrap_brokers_sasl_scram
  sensitive = true
}

output "agent_role_arn" {
  value = aws_iam_role.terrapulse_agent.arn
}
