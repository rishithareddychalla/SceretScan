import os
from typing import Tuple

GITHUB_ACTION_TEMPLATE = """name: SentinelScan CI

on:
  push:
    branches: [ "main", "master", "develop" ]
  pull_request:
    branches: [ "main", "master", "develop" ]

permissions:
  contents: read
  security-events: write # Required for uploading SARIF reports

jobs:
  sentinel-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v3
        with:
          fetch-depth: 0 # Required to scan full git history

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: "3.11"

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt

      - name: Run SentinelScan
        run: |
          # Run scan, outputting both terminal results and SARIF report
          python sentinel.py scan . --format sarif --output-file sentinel-report.sarif --severity-gate CRITICAL,HIGH

      - name: Upload SARIF results to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v2
        if: always() # Upload results even if scanning blocks the build
        with:
          sarif_file: sentinel-report.sarif
"""

def export_github_action(root_dir: str) -> Tuple[bool, str]:
    """Writes the GitHub Actions workflow file to .github/workflows/sentinel.yml."""
    workflows_dir = os.path.join(root_dir, ".github", "workflows")
    os.makedirs(workflows_dir, exist_ok=True)
    
    workflow_path = os.path.join(workflows_dir, "sentinel.yml")
    try:
        with open(workflow_path, "w", newline="\n", encoding="utf-8") as f:
            f.write(GITHUB_ACTION_TEMPLATE)
        return True, f"GitHub Actions workflow successfully written to: .github/workflows/sentinel.yml"
    except Exception as e:
        return False, f"Failed to export GitHub Actions workflow: {str(e)}"
