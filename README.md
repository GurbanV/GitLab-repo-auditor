# GitLab Repository Auditor

An audit tool for GitLab projects to check compliance with internal standards and best practices.

## Features

- Checks for protected branches.
- Analyzes project and group members (number of owners/maintainers).
- Validates the presence of essential files like README.md, LICENSE, and CHANGELOG.md.
- Assesses merge request reviews.
- Inspects CI/CD configurations for security tools (such as semgrep, trivy etc).
- Verifies fixed dependencies.
- Reports on repository health and large files.
- **Additional Checks:**
  - MR Pipeline Requirement (ensuring pipelines succeed before merging).
  - CI/CD Variables Protection and Masking.
  - Separate caches for protected branches (via .gitlab-ci.yml settings).
  - Job Timeout configuration.
  - Approvals Before Merge setting.
  - CODEOWNERS file presence.
  - Self-Approval Restriction and User Reauthentication enforcement.
  - Signed Commits enforcement via push rules.
  - Push Rules configuration.
  - Project Owners Count limits.
  - Use of protected runners and detection of group/shared runners.

## Installation

Clone the repository and install the requirements:

```bash
git clone https://github.com/GurbanV/gitlab-repo-auditor.git
cd gitlab-repo-auditor
pip install -r requirements.txt
```

## Usage
Set the required environment variables:

```bash
export GITLAB_PRIVATE_TOKEN=your_private_token
export GITLAB_URL=your_gitlab_url
```

## Run

```bash
python3 gitlab-repo-auditor.py
```

Also supports specifying arguments:

```bash
python3 gitlab-repo-auditor.py --output markdown --exclude large_files
```

## Requirements
- Python 3.x
- See requirements.txt for Python package dependencies.

## License
This project is licensed under the MIT License.
