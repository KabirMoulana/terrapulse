# TerraPulse 🌍

**GitOps-driven Multi-cloud Infrastructure Drift Detection & Policy Enforcement Engine**

[![CI](https://github.com/yourusername/terrapulse/actions/workflows/ci.yml/badge.svg)](https://github.com/yourusername/terrapulse/actions)
[![OPA Policies](https://img.shields.io/badge/OPA-Policy%20Tests-blue)](policies/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

TerraPulse continuously scans AWS, GCP, and Azure resources, evaluates them against OPA policies, detects drift from Terraform desired state, and auto-remediates approved deviations — with an immutable audit trail.

> Console change → drift detected → alert in < 60 seconds → auto-remediated (if approved policy) or human approval requested.

## Architecture

```
  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
  │  AWS Agent  │     │  GCP Agent  │     │ Azure Agent │
  │  (Go)       │     │  (Go)       │     │  (Go)       │
  │  IRSA auth  │     │  WLI auth   │     │  MI auth    │
  └──────┬──────┘     └──────┬──────┘     └──────┬──────┘
         │                   │                   │
         └───────────────────┼───────────────────┘
                             │  Kafka (MSK)
                             │  drift-events topic
                             ▼
                   ┌──────────────────────┐
                   │  Policy Engine       │
                   │  (OPA + Go wrapper)  │
                   │  - Evaluates Rego    │
                   │  - Compares vs IaC   │
                   │  - Scores violations │
                   └──────────┬───────────┘
                              │
              ┌───────────────┴────────────────┐
              ▼                                ▼
   ┌─────────────────────┐        ┌────────────────────────┐
   │  Violation Store    │        │  Remediation Dispatcher│
   │  (PostgreSQL)       │        │  - Rate limited        │
   │  - Drift history    │        │  - Blast radius guard  │
   │  - Audit log (S3    │        │  - Dispatches to agent │
   │    Object Lock)     │        │    that owns resource  │
   └─────────────────────┘        └────────────────────────┘
              │
              ▼
   ┌─────────────────────┐
   │  Dashboard (React)  │
   │  - Drift heatmap    │
   │  - Policy scores    │
   │  - Remediation log  │
   └─────────────────────┘
```

## Quick Start

```bash
git clone https://github.com/yourusername/terrapulse
cd terrapulse

# Run the agent locally against your AWS account
# Uses your local ~/.aws/credentials
go run ./agent/cmd/main.go \
  --cloud-provider aws \
  --region us-east-1 \
  --control-plane-url http://localhost:8080 \
  --scan-interval 60s

# Run policy tests (no cloud account needed)
opa test policies/ -v

# Start full local stack
docker-compose up -d
```

## OPA Policies

Policies are written in Rego and **unit tested** with `opa test`:

```bash
opa test policies/ -v --coverage
# PASS: 14/14 tests in 0.023s
# Coverage: 94.2%
```

Policies enforce:

| Policy | Severity | Auto-Remediate |
|---|---|---|
| SG open to 0.0.0.0/0 on sensitive ports | CRITICAL | ❌ (requires approval) |
| S3 public access not blocked | CRITICAL | ✅ |
| S3 versioning disabled | HIGH | ✅ |
| S3 encryption disabled | HIGH | ✅ |
| RDS publicly accessible | CRITICAL | ❌ |
| RDS missing deletion protection (prod) | HIGH | ✅ |
| Missing required tags | MEDIUM | ❌ |

## Agent Distribution

Agents are released as **signed, multi-platform binaries** via goreleaser + cosign:

```bash
# Download and verify
curl -LO https://github.com/yourusername/terrapulse/releases/latest/download/terrapulse-agent_linux_amd64.tar.gz
curl -LO https://github.com/yourusername/terrapulse/releases/latest/download/checksums.txt

# Verify signature (supply chain security)
cosign verify-blob \
  --signature checksums.txt.sig \
  --certificate checksums.txt.pem \
  checksums.txt

sha256sum -c checksums.txt
```

## Zero Static Credentials

Each agent uses cloud-native auth — no static keys:

| Cloud | Auth Method |
|---|---|
| AWS | IRSA (IAM Roles for Service Accounts) |
| GCP | Workload Identity |
| Azure | Managed Identity |

Agent IAM roles are **least privilege**: read-only scan + only the specific remediation API calls needed.

## Drift Detection Demo

```bash
# 1. Tag an EC2 security group with a rule allowing SSH from 0.0.0.0/0
aws ec2 authorize-security-group-ingress \
  --group-id sg-12345678 \
  --protocol tcp --port 22 --cidr 0.0.0.0/0

# 2. Within 60s, TerraPulse detects the drift
# Dashboard shows: CRITICAL violation — sg-12345678 allows 0.0.0.0/0 on port 22

# 3. Auto-remediation (if policy approved) revokes the rule
# Audit log in S3: immutable record of the change
```

## Project Structure

```
terrapulse/
├── agent/                    # Go drift-detection agent (deployed per cloud account)
│   ├── cmd/                  # Entrypoint
│   └── internal/
│       ├── scanner/          # Multi-cloud resource scanner (AWS, GCP, Azure)
│       ├── publisher/        # Publishes snapshots to control plane via Kafka
│       └── reconciler/       # Applies remediation actions
├── control-plane/            # Go API server — receives snapshots, dispatches remediations
├── policy-engine/            # Go OPA wrapper — evaluates Rego policies
├── policies/
│   ├── rules/                # Rego policies (aws_policies.rego, gcp_policies.rego, etc.)
│   └── rules/*_test.rego     # Policy unit tests (co-located with policies)
├── infra/terraform/
│   ├── aws/                  # EKS, MSK, S3, IAM (agent role)
│   ├── gcp/                  # GKE, Pub/Sub, Workload Identity
│   └── azure/                # AKS, Event Hub, Managed Identity
├── deploy/helm/terrapulse/   # Helm chart for control plane
├── .goreleaser.yaml          # Multi-platform signed binary releases
└── docs/adr/                 # Architecture Decision Records
```

## Architecture Decision Records

- [ADR-001: OPA for policy engine vs custom Go rules](docs/adr/001-opa-policy-engine.md)
- [ADR-002: Kafka vs SQS for drift events](docs/adr/002-kafka-vs-sqs.md)
- [ADR-003: Agent as binary vs container](docs/adr/003-agent-deployment.md)
- [ADR-004: S3 Object Lock for audit trail immutability](docs/adr/004-audit-immutability.md)

## License

MIT
