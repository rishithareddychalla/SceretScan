import json
from typing import List, Dict, Any, Tuple

def mask_secret(secret: str) -> str:
    """Masks a secret to prevent accidental exposure while keeping it identifiable."""
    if not secret:
        return ""
    length = len(secret)
    if length <= 6:
        return "*" * length
    if length <= 12:
        return secret[:2] + "*" * (length - 4) + secret[-2:]
    # For longer secrets, keep first 4 and last 4 characters
    return secret[:4] + "*" * (length - 8) + secret[-4:]

def calculate_security_score(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Calculates the overall security score for the scanned environment.
    Starts at 100, deducts points based on the severity of unique findings.
    """
    score = 100.0
    deductions = {
        "CRITICAL": 15.0,
        "HIGH": 10.0,
        "MEDIUM": 5.0,
        "LOW": 2.0
    }
    
    # We deduct based on UNIQUE secrets to prevent artificial scoring drops from duplicate files
    seen_secrets = set()
    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0
    
    for f in findings:
        secret = f.get("secret", "")
        severity = f.get("severity", "MEDIUM").upper()
        
        # Track counts
        if severity == "CRITICAL":
            critical_count += 1
        elif severity == "HIGH":
            high_count += 1
        elif severity == "MEDIUM":
            medium_count += 1
        elif severity == "LOW":
            low_count += 1
            
        if secret not in seen_secrets:
            seen_secrets.add(secret)
            deduction = deductions.get(severity, 5.0)
            score -= deduction

    score = max(0.0, score)
    
    # Determine grade
    if score >= 90:
        grade = "A"
        status = "EXCELLENT"
    elif score >= 80:
        grade = "B"
        status = "GOOD"
    elif score >= 70:
        grade = "C"
        status = "FAIR"
    elif score >= 50:
        grade = "D"
        status = "POOR"
    else:
        grade = "F"
        status = "CRITICAL"
        
    return {
        "security_score": round(score, 1),
        "grade": grade,
        "status": status,
        "counts": {
            "CRITICAL": critical_count,
            "HIGH": high_count,
            "MEDIUM": medium_count,
            "LOW": low_count,
            "TOTAL": len(findings)
        }
    }

def detect_duplicates(findings: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], Dict[str, List[Dict[str, Any]]]]:
    """
    Groups findings to separate unique findings from duplicate findings.
    Returns:
        - unique_findings: List of first occurrences.
        - duplicates_map: Dictionary mapping secret values to all their finding details.
    """
    unique_findings = []
    duplicates_map = {}
    seen_secrets = set()
    
    for f in findings:
        secret = f.get("secret")
        if not secret:
            continue
            
        if secret not in duplicates_map:
            duplicates_map[secret] = []
        duplicates_map[secret].append(f)
        
        if secret not in seen_secrets:
            seen_secrets.add(secret)
            unique_findings.append(f)
            
    return unique_findings, duplicates_map

def compare_snapshots(old_snapshot_path: str, current_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Compares current scan findings with a previous snapshot JSON report.
    Returns categorized findings: new, resolved, and unchanged.
    """
    try:
        with open(old_snapshot_path, "r", encoding="utf-8") as f:
            old_data = json.load(f)
            
        # Extract findings list from old report
        old_findings = []
        if isinstance(old_data, list):
            old_findings = old_data
        elif isinstance(old_data, dict):
            old_findings = old_data.get("findings", [])
    except Exception as e:
        return {
            "error": f"Failed to read snapshot: {str(e)}",
            "new": current_findings,
            "resolved": [],
            "unchanged": []
        }
        
    # Helper to generate unique key for a finding
    def make_finding_key(finding: Dict[str, Any]) -> str:
        # Match by file path, rule_id, and secret value
        return f"{finding.get('file_path', '')}:{finding.get('rule_id', '')}:{finding.get('secret', '')}"
        
    old_map = {make_finding_key(f): f for f in old_findings}
    current_map = {make_finding_key(f): f for f in current_findings}
    
    new_findings = []
    resolved_findings = []
    unchanged_findings = []
    
    for key, f in current_map.items():
        if key not in old_map:
            new_findings.append(f)
        else:
            unchanged_findings.append(f)
            
    for key, f in old_map.items():
        if key not in current_map:
            resolved_findings.append(f)
            
    return {
        "new": new_findings,
        "resolved": resolved_findings,
        "unchanged": unchanged_findings,
        "comparison_summary": {
            "new_count": len(new_findings),
            "resolved_count": len(resolved_findings),
            "unchanged_count": len(unchanged_findings)
        }
    }
