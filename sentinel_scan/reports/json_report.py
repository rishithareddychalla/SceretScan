import json
from typing import List, Dict, Any

def generate_json_report(
    findings: List[Dict[str, Any]],
    risk_summary: Dict[str, Any],
    gitignore_audit: List[str],
    output_path: str
) -> None:
    """Generates a structured JSON report of the scan findings."""
    report_data = {
        "generator": "SentinelScan",
        "version": "1.0.0",
        "summary": risk_summary,
        "gitignore_audit_unignored_files": gitignore_audit,
        "findings": findings
    }
    
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2, ensure_ascii=False)
