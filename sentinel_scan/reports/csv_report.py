import csv
from typing import List, Dict, Any
from sentinel_scan.core.risk_engine import mask_secret

def generate_csv_report(findings: List[Dict[str, Any]], output_path: str) -> None:
    """Generates a CSV report of the scan findings with masked secrets."""
    headers = [
        "Rule ID", "Rule Name", "Severity", "Category", 
        "File Path", "Line Number", "Start Column", 
        "Secret (Masked)", "In History", "Commit Hash", "Description"
    ]
    
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        
        for fnd in findings:
            writer.writerow([
                fnd.get("rule_id", ""),
                fnd.get("rule_name", ""),
                fnd.get("severity", ""),
                fnd.get("category", ""),
                fnd.get("file_path", ""),
                fnd.get("line_number", ""),
                fnd.get("start_column", ""),
                mask_secret(fnd.get("secret", "")),
                fnd.get("in_history", False),
                fnd.get("commit_hash", "N/A"),
                fnd.get("description", "")
            ])
