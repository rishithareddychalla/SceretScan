import datetime
from typing import List, Dict, Any
from sentinel_scan.core.risk_engine import mask_secret

def generate_markdown_report(
    findings: List[Dict[str, Any]],
    risk_summary: Dict[str, Any],
    gitignore_audit: List[str],
    output_path: str
) -> None:
    """Generates a beautiful markdown report with badges, summaries, and action items."""
    
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    score = risk_summary.get("security_score", 100.0)
    grade = risk_summary.get("grade", "A")
    status = risk_summary.get("status", "EXCELLENT")
    counts = risk_summary.get("counts", {})
    
    # Choose badge color
    if score >= 90:
        badge_color = "brightgreen"
    elif score >= 80:
        badge_color = "green"
    elif score >= 70:
        badge_color = "yellow"
    elif score >= 50:
        badge_color = "orange"
    else:
        badge_color = "red"
        
    md = []
    md.append(f"# SentinelScan Security Audit Report")
    md.append(f"Generated on: `{now}`\n")
    md.append(f"![Security Score](https://img.shields.io/badge/Security_Score-{score}%2F100-{badge_color}?style=for-the-badge)")
    md.append(f"![Grade](https://img.shields.io/badge/Grade-{grade}-{badge_color}?style=for-the-badge)")
    md.append(f"![Status](https://img.shields.io/badge/Status-{status}-{badge_color}?style=for-the-badge)\n")
    
    md.append("## Executive Summary")
    md.append("| Metric | Value |")
    md.append("| :--- | :--- |")
    md.append(f"| **Security Score** | `{score} / 100` |")
    md.append(f"| **Overall Grade** | `{grade}` ({status}) |")
    md.append(f"| **Critical Severity Secrets** | `{counts.get('CRITICAL', 0)}` |")
    md.append(f"| **High Severity Secrets** | `{counts.get('HIGH', 0)}` |")
    md.append(f"| **Medium Severity Secrets** | `{counts.get('MEDIUM', 0)}` |")
    md.append(f"| **Low Severity Secrets** | `{counts.get('LOW', 0)}` |")
    md.append(f"| **Total Leaks Found** | `{counts.get('TOTAL', 0)}` |\n")
    
    # Gitignore Audit section
    md.append("## 🛡️ .gitignore Audit Status")
    if gitignore_audit:
        md.append("> [!WARNING]")
        md.append("> **Unignored sensitive files detected!** The following files contain credentials/configuration but are not listed in `.gitignore`. They risk being pushed to remote servers:")
        for file in gitignore_audit:
            md.append(f"- [ ] `{file}`")
        md.append("\n*To automatically ignore these files, run: `python sentinel.py fix gitignore`*\n")
    else:
        md.append("✅ **Clean audit.** All standard sensitive files (e.g. `.env`, SSH keys) are properly listed in your `.gitignore` or do not exist in the workspace.\n")
        
    # Separate active findings and history findings
    active_findings = [f for f in findings if not f.get("in_history", False)]
    history_findings = [f for f in findings if f.get("in_history", False)]
    
    # Active findings table
    md.append("## 📁 Active File Leaks")
    if active_findings:
        md.append("| Secret Type | Severity | File Path | Line:Col | Masked Secret |")
        md.append("| :--- | :--- | :--- | :--- | :--- |")
        for f in active_findings:
            line_col = f"{f.get('line_number', 'N/A')}:{f.get('start_column', 'N/A')}"
            md.append(f"| {f.get('rule_name')} | `{f.get('severity')}` | `{f.get('file_path')}` | `{line_col}` | `{mask_secret(f.get('secret'))}` |")
        md.append("")
    else:
        md.append("✅ No secrets found in active files.\n")
        
    # Git history timeline
    md.append("## ⏳ Git History Leak Timeline")
    if history_findings:
        # Sort history findings by date (oldest first or newest first, let's do newest first)
        history_findings_sorted = sorted(history_findings, key=lambda x: x.get("commit_date", ""), reverse=True)
        md.append("| Commit Hash | Date | Author | File Path | Secret Type |")
        md.append("| :--- | :--- | :--- | :--- | :--- |")
        for f in history_findings_sorted:
            hsh = f.get("commit_hash", "")[:8]
            md.append(f"| `{hsh}` | `{f.get('commit_date', '')[:10]}` | {f.get('commit_author')} | `{f.get('file_path')}` | {f.get('rule_name')} |")
        md.append("")
    else:
        md.append("✅ No secrets found in Git commit history.\n")
        
    # Detailed findings cards
    md.append("## 🔍 Detailed Remediation Guidance")
    if findings:
        for idx, f in enumerate(findings, start=1):
            source_type = "Historical Commit" if f.get("in_history") else "Active File"
            md.append(f"### {idx}. {f.get('rule_name')} ({f.get('severity')})")
            md.append(f"- **Source:** {source_type}")
            md.append(f"- **File:** `{f.get('file_path')}`")
            if not f.get("in_history"):
                md.append(f"- **Line:** `{f.get('line_number')}`")
            else:
                md.append(f"- **Commit:** `{f.get('commit_hash', '')[:8]}` - *\"{f.get('commit_message')}\"*")
            md.append(f"- **Masked Secret:** `{mask_secret(f.get('secret'))}`")
            md.append(f"\n**Risk Description:**\n{f.get('description')}\n")
            md.append(f"**Remediation Steps:**\n{f.get('remediation')}\n")
            md.append("---")
    else:
        md.append("No secrets detected. Your codebase is secure!")
        
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(md))
