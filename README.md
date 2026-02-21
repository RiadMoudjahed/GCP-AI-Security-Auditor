<div align="center">

# GCP AI Security Auditor

An automated security auditing tool for Google Cloud Platform environments hosting AI and machine learning workloads. The tool identifies misconfigurations across Vertex AI, Cloud Storage, and IAM resources that general-purpose scanners do not address.

[![CI/CD Pipeline](https://github.com/RiadMoudjahed/GCP-AI-Security-Auditor/actions/workflows/devsecops_pipeline.yml/badge.svg?branch=main)](https://github.com/RiadMoudjahed/GCP-AI-Security-Auditor/actions/workflows/devsecops_pipeline.yml)

![License](https://img.shields.io/badge/license-MIT-green)

</div>

---

## Overview

AI and machine learning workloads introduce a distinct attack surface that infrastructure-level security tools are not designed to assess. This tool performs targeted audits across three security domains relevant to GCP-hosted AI environments.

**Vertex AI**
- Notebook instances with public IP addresses
- Notebook instances with unrestricted proxy access

**Cloud Storage**
- Model artifact buckets with inherited public access prevention
- Buckets without customer-managed encryption keys (KMS)

**Identity and Access Management**
- Project-level bindings granted to `allUsers` or `allAuthenticatedUsers`
- Primitive roles (`roles/owner`, `roles/editor`) assigned to any principal
- Service accounts holding owner or editor permissions

---

## How This Differs from GCP-Security-Scanner

This project is a continuation and specialization of [GCP-Security-Scanner](https://github.com/RiadMoudjahed/GCP-Security-Scanner), my previous general-purpose GCP auditing tool. The two projects serve different purposes.

| | GCP-Security-Scanner | GCP-AI-Security-Auditor |
|---|---|---|
| **Target** | General GCP infrastructure | AI/ML workloads specifically |
| **Checks** | IAM, Firewall, Storage | Vertex AI, Storage, IAM |
| **Firewall audit** | ✅ | ❌ |
| **Notebook security** | ❌ | ✅ |
| **KMS encryption audit** | ❌ | ✅ |
| **Use case** | Broad infrastructure review | AI deployment security review |
| **Architecture** | Flat `scanner/` modules | Modular `auditor/` package |

The previous scanner is the right tool for auditing general GCP infrastructure. This tool is the right tool when the question is specifically: *"Is my GCP environment safe to deploy AI workloads on?"*

---

## Requirements

- Python 3.11 or later
- Google Cloud SDK installed and authenticated
- A GCP service account or user account with the following roles: `roles/viewer`, `roles/iam.securityReviewer`
- The following GCP APIs enabled on the target project:
  - Notebooks API (`notebooks.googleapis.com`)
  - Cloud Storage API (`storage.googleapis.com`)
  - Cloud Resource Manager API (`cloudresourcemanager.googleapis.com`)

---

## Installation

**1. Clone the repository**
```bash
git clone https://github.com/RiadMoudjahed/GCP-AI-Security-Auditor.git
cd GCP-AI-Security-Auditor
```

**2. Create and activate a virtual environment**
```bash
python3 -m venv venv
source venv/bin/activate
```

**3. Install dependencies**
```bash
pip install -r requirements.txt
```

---

## Usage

**1. Authenticate with GCP**
```bash
gcloud auth application-default login
```

**2. Enable required APIs on your target project**
```bash
gcloud services enable notebooks.googleapis.com --project=YOUR_PROJECT_ID
gcloud services enable storage.googleapis.com --project=YOUR_PROJECT_ID
gcloud services enable cloudresourcemanager.googleapis.com --project=YOUR_PROJECT_ID
```

**3. Set your project ID as an environment variable**
```bash
export GCP_PROJECT_ID="YOUR_PROJECT_ID"
```

**4. Run the auditor**
```bash
python3 auditor/core/auditor.py
```

**5. Review the report**

The tool will print a full findings report to stdout, grouped by severity. Example output from a live GCP environment:

```
==================================================
GCP AI Security Audit Report - Project: qwiklabs-gcp-04-ex7cx-6f94
==================================================

HIGH: iam-security - serviceAccount:123456789-compute@developer.gserviceaccount.com, serviceAccount:123456789@cloudservices.gserviceaccount.com IAM binding on role: roles/editor

CRITICAL: iam-security - Service account with owner/editor role: serviceAccount:123456789-compute@developer.gserviceaccount.com

CRITICAL: iam-security - Service account with owner/editor role: serviceAccount:123456789@cloudservices.gserviceaccount.com

HIGH: iam-security - serviceAccount:admiral@qwiklabs-services-prod.iam.gserviceaccount.com, user:student-01-0370f79bbd0b@qwiklabs.net IAM binding on role: roles/owner

CRITICAL: iam-security - Service account with owner/editor role: serviceAccount:admiral@qwiklabs-services-prod.iam.gserviceaccount.com

CRITICAL: iam-security - Service account with owner/editor role: serviceAccount:qwiklabs-gcp-04-ex7cx-6f94@qwiklabs-gcp-04-ex7cx-6f94.iam.gserviceaccount.com

==================================================
Total findings: 6
0 MEDIUM
2 HIGH
4 CRITICAL
==================================================
```

---

## Real-World Results

The tool was tested against a live GCP environment. The following findings were detected automatically:

| Severity | Check | Finding |
|---|---|---|
| CRITICAL | iam-security | Default compute service account has `roles/editor` |
| CRITICAL | iam-security | Cloud services service account has `roles/editor` |
| CRITICAL | iam-security | Service account has `roles/owner` |
| CRITICAL | iam-security | Project service account has `roles/owner` |
| HIGH | iam-security | Primitive role `roles/editor` assigned to service accounts |
| HIGH | iam-security | Primitive role `roles/owner` assigned to multiple principals |

**Key takeaway:** 100% of tested GCP projects had service accounts with overly permissive primitive roles. This is a common default configuration that violates the principle of least privilege and represents a significant risk for AI workloads, where pipelines run as service accounts.

---

## Security Rules Explained

**Public Notebook Instances**
Vertex AI notebook instances with a public IP are directly reachable from the internet. An exposed notebook means exposed training data, model weights, and any GCP credentials loaded into the runtime environment.

**Unencrypted Model Storage**
Buckets without customer-managed KMS keys rely on Google-managed encryption alone. Adding KMS provides a second layer of access control that remains enforced even if bucket ACLs are misconfigured.

**Overprivileged Service Accounts**
ML pipelines run as service accounts. Assigning `roles/owner` or `roles/editor` to these accounts grants hundreds of permissions far beyond what a pipeline requires. A compromised pipeline can then exfiltrate data, delete resources, or spin up infrastructure.

**Public IAM Bindings**
Granting `allUsers` or `allAuthenticatedUsers` any role on a project exposes all resources to unauthenticated or broadly authenticated principals.

---

## Project Structure

```
GCP-AI-Security-Auditor/
├── auditor/
│   ├── core/
│   │   └── auditor.py          # Core auditor class — all checks live here
│   └── main.py                 # Entry point
├── tests/
│   └── test_auditor.py         # 6 unit tests, 83% coverage
├── .github/workflows/
│   └── devsecops_pipeline.yml  # DevSecOps CI/CD pipeline
├── requirements.txt
└── README.md
```

---

## Testing

The test suite includes six unit tests with 83% code coverage, enforced automatically by the CI/CD pipeline.

```bash
pytest tests/ --cov=auditor --cov-report=term-missing -v
```

---

## CI/CD Pipeline

The pipeline executes three sequential stages on every push to `main` or `dev` and on all pull requests targeting `main`.

**Stage 1 — Static Application Security Testing**
Bandit scans the Python source code for security vulnerabilities at medium severity and confidence thresholds. This stage must pass before subsequent stages execute.

**Stage 2 — Dependency Vulnerability Scanning**
Safety checks all declared dependencies in `requirements.txt` against known CVE databases to identify vulnerable library versions.

**Stage 3 — Automated Testing and Coverage Enforcement**
Pytest executes the full test suite only after both security stages have passed. A minimum coverage threshold of 70% is enforced; builds below this threshold fail automatically.

This design follows a shift-left security approach: security validation occurs before functional testing, ensuring that insecure or vulnerable code does not proceed through the pipeline.

---

## Planned Enhancements

- VPC Service Controls validation for AI APIs
- Cloud Logging audit for Vertex AI model endpoints
- Vertex AI model registry permission assessment
- JSON and CSV report export formats
- Severity-based exit codes for downstream CI/CD integration
- Security Command Center integration
- Alerting for critical findings via Slack or email

---

## License

MIT License

---

## Author

Riad Moudjahed

*Part of my cloud security learning journey. For general GCP infrastructure auditing, see [GCP-Security-Scanner](https://github.com/RiadMoudjahed/GCP-Security-Scanner).*
