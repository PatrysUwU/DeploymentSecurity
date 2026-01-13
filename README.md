# DeploymentSecurity

A comprehensive security scanner for containerized applications and deployment configurations.

## Overview

DeploymentSecurity is a multi-tool security analysis platform that scans containerized applications for vulnerabilities, misconfigurations, and security issues. It integrates multiple security scanners and provides automated remediation suggestions.

## Quick Start

```bash
# Clone and setup
git clone <repository-url>
cd DeploymentSecurity

# Install dependencies
pip install -r backend/requirements.txt

# Scan your project
python -m deployment_scanner.cli scan --proj_path /path/to/your/project

# View results
cat /path/to/your/project/scan_results.json

# Generate fixes
python -m deployment_scanner.cli remediate --proj_path /path/to/your/project
```

## Features

- **Container Image Scanning**: Vulnerability detection in Docker images using Trivy
- **Dependency Analysis**: Security scanning of package-lock.json, requirements.txt, and other dependency files
- **Static Code Analysis**: Python code security analysis using Bandit
- **Configuration Security**: Docker Compose and deployment configuration validation
- **Automated Remediation**: Generates secure alternatives for identified issues
- **Security Scoring**: Comprehensive security assessment with weighted scoring

## Installation

### Prerequisites

- Python 3.8+
- Docker
- Trivy
- Bandit

### Install Dependencies

```bash
pip install -r backend/requirements.txt
```

### Install Security Tools

```bash
# Install Trivy
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Install Bandit
pip install bandit
```

## Usage

### Command Line Interface

#### Scan Project
```bash
python -m deployment_scanner.cli scan --proj_path /path/to/project
```

#### Generate Remediatiated files
```bash
python -m deployment_scanner.cli remediate --proj_path /path/to/project
```


## Scan Types

### 1. Container Image Vulnerabilities
- Scans Docker images for known CVEs
- Provides severity ratings and fix information

### 2. Dependency Security
- Scans package-lock.json, requirements.txt, yarn.lock
- Identifies vulnerable packages
- Suggests version updates

### 3. Static Code Analysis
- Python security analysis with Bandit
- Identifies common security antipatterns
- Flags potential vulnerabilities

### 4. Configuration Security
- Docker Compose security validation
- Deployment configuration analysis
- Security best practices enforcement

## Output

### Scan Results
Results are saved to `scan_results.json` containing:
- Vulnerability details with CVE information
- Security misconfigurations
- Code security issues
- Overall security score

### Remediation
Auto-generated fixes in `/remediation` directory:
- Updated Docker Compose files
- Patched code examples
- Configuration improvements

## Security Scoring

The platform calculates a weighted security score based on:
- Dependencyvulnerabilities (40%)
- Misconfigurations (35%)
- Code issues (25%)

Scores range from 0-100, with higher scores indicating better security status.

### Docker Compose Security Checks
- Privileged container detection
- Exposed sensitive ports
- Insecure volume mounts
- Missing security contexts
