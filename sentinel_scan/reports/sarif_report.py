import json
from typing import List, Dict, Any

def severity_to_sarif_level(severity: str) -> str:
    """Maps SentinelScan severity to SARIF levels (error, warning, note, none)."""
    sev = severity.upper()
    if sev in ("CRITICAL", "HIGH"):
        return "error"
    elif sev == "MEDIUM":
        return "warning"
    else:
        return "note"

def generate_sarif_report(findings: List[Dict[str, Any]], output_path: str) -> None:
    """
    Generates a SARIF v2.1.0 compliant report for static analysis integration.
    """
    # Define rules metadata
    rules_map = {}
    from sentinel_scan.core.rules import SECRET_RULES
    
    for r in SECRET_RULES:
        rules_map[r.rule_id] = {
            "id": r.rule_id,
            "shortDescription": {"text": r.name},
            "fullDescription": {"text": r.description},
            "defaultConfiguration": {
                "level": severity_to_sarif_level(r.severity)
            },
            "helpUri": "https://github.com/sentinelscan/sentinelscan"
        }
        
    # High entropy generic rule
    if "high-entropy-secret" not in rules_map:
        rules_map["high-entropy-secret"] = {
            "id": "high-entropy-secret",
            "shortDescription": {"text": "High Entropy Secret"},
            "fullDescription": {"text": "A string with high Shannon entropy was detected, indicating a potential credential."},
            "defaultConfiguration": {
                "level": "warning"
            },
            "helpUri": "https://github.com/sentinelscan/sentinelscan"
        }

    results = []
    for f in findings:
        rule_id = f.get("rule_id", "high-entropy-secret")
        severity_level = severity_to_sarif_level(f.get("severity", "MEDIUM"))
        
        # Determine locations
        loc = {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": f.get("file_path", "").replace('\\', '/')
                }
            }
        }
        
        # Add region information if line numbers are present
        line = f.get("line_number")
        if line is not None:
            region = {"startLine": line}
            start_col = f.get("start_column")
            end_col = f.get("end_column")
            if start_col is not None:
                region["startColumn"] = start_col
            if end_col is not None:
                region["endColumn"] = end_col
            loc["physicalLocation"]["region"] = region
            
        results.append({
            "ruleId": rule_id,
            "level": severity_level,
            "message": {
                "text": f"{f.get('rule_name', 'Secret')}: {f.get('description', '')}\nRemediation: {f.get('remediation', '')}"
            },
            "locations": [loc],
            "properties": {
                "in_history": f.get("in_history", False),
                "commit_hash": f.get("commit_hash", ""),
                "commit_author": f.get("commit_author", "")
            }
        })
        
    sarif_data = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SentinelScan",
                        "semanticVersion": "1.0.0",
                        "informationUri": "https://github.com/sentinelscan/sentinelscan",
                        "rules": list(rules_map.values())
                    }
                },
                "results": results
            }
        ]
    }
    
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sarif_data, f, indent=2, ensure_ascii=False)
