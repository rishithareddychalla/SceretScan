import os
import sys
import argparse
from typing import List, Dict, Any

# Rich imports for outstanding terminal aesthetics
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.columns import Columns
from rich.align import Align
from rich.progress import Progress, SpinnerColumn, TextColumn

from sentinel_scan.core.scanner import scan_directory, scan_file, scan_zip_file
from sentinel_scan.core.risk_engine import (
    calculate_security_score,
    detect_duplicates,
    compare_snapshots,
    mask_secret
)
from sentinel_scan.remediation.ai_explainer import get_ai_explanation
from sentinel_scan.remediation.fixer import audit_gitignore, fix_gitignore, install_pre_commit_hook
from sentinel_scan.integrations.github_action import export_github_action
from sentinel_scan.sources.github_source import clone_and_scan_github_repo

console = Console()

BANNER = r"""
   _____            _   _             _  _____                     
  / ____|          | | (_)           | |/ ____|                    
 | (___   ___ _ __ | |_ _ _ __   ___ | | (___   ___ __ _ _ __      
  \___ \ / _ \ '_ \| __| | '_ \ / _ \| |\___ \ / __/ _` | '_ \     
  ____) |  __/ | | | |_| | | | |  __/| |____) | (_| (_| | | | |    
 |_____/ \___|_| |_|\__|_|_| |_|\___||_|_____/ \___\__,_|_| |_|    
"""

def show_banner():
    console.print(Align.center(Text(BANNER, style="bold purple")), justify="center")
    console.print(Align.center("[bold white]🛡️  SentinelScan Security Platform • Production Grade Secret Scanner[/]"), justify="center")
    console.print(Align.center("[slate_blue]Resembling GitGuardian, GitHub Secret Scanning, Gitleaks & TruffleHog[/]"), justify="center")
    console.print()

def format_severity(severity: str) -> Text:
    sev = severity.upper()
    if sev == "CRITICAL":
        return Text(sev, style="bold red")
    elif sev == "HIGH":
        return Text(sev, style="bold orange1")
    elif sev == "MEDIUM":
        return Text(sev, style="bold yellow")
    else:
        return Text(sev, style="bold green")

def print_summary_panel(risk_summary: Dict[str, Any]):
    score = risk_summary["security_score"]
    grade = risk_summary["grade"]
    status = risk_summary["status"]
    counts = risk_summary["counts"]
    
    # Choose color based on score
    if score >= 90:
        score_style = "bold green"
    elif score >= 80:
        score_style = "bold chartreuse3"
    elif score >= 70:
        score_style = "bold yellow"
    elif score >= 50:
        score_style = "bold orange1"
    else:
        score_style = "bold red"
        
    summary_text = Text()
    summary_text.append("🛡️  Project Security Posture\n\n", style="bold white")
    summary_text.append(f"Security Score : ", style="white")
    summary_text.append(f"{score} / 100\n", style=score_style)
    summary_text.append(f"Security Grade : ", style="white")
    summary_text.append(f"{grade} ({status})\n\n", style=score_style)
    summary_text.append("Findings Breakdown:\n", style="bold white")
    summary_text.append(f"🔴 CRITICAL : {counts.get('CRITICAL', 0)}\n", style="red")
    summary_text.append(f"🟠 HIGH     : {counts.get('HIGH', 0)}\n", style="orange1")
    summary_text.append(f"🟡 MEDIUM   : {counts.get('MEDIUM', 0)}\n", style="yellow")
    summary_text.append(f"🟢 LOW      : {counts.get('LOW', 0)}\n", style="green")
    summary_text.append(f"📊 TOTAL    : {counts.get('TOTAL', 0)}\n", style="bold white")
    
    panel = Panel(
        summary_text,
        title="[bold purple]Scan Dashboard[/]",
        border_style="purple",
        expand=False
    )
    console.print(panel)

def run_cli():
    parser = argparse.ArgumentParser(description="SentinelScan: Production-grade Secret Scanner")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Scan parser
    scan_parser = subparsers.add_parser("scan", help="Scan a directory, file, ZIP or GitHub repo")
    scan_parser.add_argument("target", nargs="?", default=".", help="Path to scan (default: current directory)")
    scan_parser.add_argument("--exclude-history", action="store_true", help="Exclude Git history/commit scanning")
    scan_parser.add_argument("--github", action="store_true", help="Scan a GitHub repository URL instead of a local path")
    scan_parser.add_argument("--github-token", help="GitHub Personal Access Token for private repositories")
    scan_parser.add_argument("--zip", action="store_true", help="Scan a ZIP archive file")
    scan_parser.add_argument("--format", choices=["console", "json", "csv", "markdown", "sarif", "html"], default="console", help="Report format (or 'console' to print table)")
    scan_parser.add_argument("--output-file", help="Path to save report (optional unless format is specified)")
    scan_parser.add_argument("--severity-gate", help="Comma-separated severity levels (CRITICAL,HIGH,etc.) to trigger non-zero exit code")
    scan_parser.add_argument("--explain", action="store_true", help="Show AI/DevSecOps explanation for each detected secret")
    scan_parser.add_argument("-w", "--watch", action="store_true", help="Enable watch mode to monitor file changes in real-time")
    
    # Fix parser
    fix_parser = subparsers.add_parser("fix", help="Audit and resolve repository configuration issues")
    fix_parser.add_argument("action", choices=["gitignore"], help="Action to execute (gitignore)")
    
    # Install hook parser
    subparsers.add_parser("install-hook", help="Install Git pre-commit hook that blocks secret commits")
    
    # Export CI parser
    subparsers.add_parser("export-ci", help="Export a GitHub Actions CI workflow template")
    
    # Compare parser
    compare_parser = subparsers.add_parser("compare", help="Compare current scans against a snapshot")
    compare_parser.add_argument("snapshot", help="Path to past JSON scan report snapshot")
    compare_parser.add_argument("target", nargs="?", default=".", help="Path to current scan target")
    
    # Web parser
    web_parser = subparsers.add_parser("web", help="Launch the interactive web UI dashboard")
    web_parser.add_argument("--port", type=int, default=5000, help="Port to run web server on (default: 5000)")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(0)
        
    show_banner()
    
    if args.command == "scan":
        if args.watch:
            # Watch Mode
            run_watch_mode(args.target)
        else:
            # Standard Scan Mode
            run_scan(args)
            
    elif args.command == "fix":
        if args.action == "gitignore":
            run_gitignore_fix()
            
    elif args.command == "install-hook":
        run_install_hook()
        
    elif args.command == "export-ci":
        run_export_ci()
        
    elif args.command == "compare":
        run_compare(args.snapshot, args.target)
        
    elif args.command == "web":
        from web_ui import start_web_server
        start_web_server(args.port)

def run_scan(args):
    target = args.target
    scan_git_history = not args.exclude_history
    
    findings = []
    
    # 1. Determine scan target type and invoke correct scanner
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            
            if args.github:
                progress.add_task(description=f"Cloning and scanning remote GitHub repo: {target}...", total=None)
                findings = clone_and_scan_github_repo(target, github_token=args.github_token, scan_history=scan_git_history)
            elif args.zip or target.endswith(".zip"):
                progress.add_task(description=f"Scanning ZIP archive: {target}...", total=None)
                findings = scan_zip_file(target)
            elif os.path.isfile(target):
                progress.add_task(description=f"Scanning file: {target}...", total=None)
                findings = scan_file(target)
            elif os.path.isdir(target):
                progress.add_task(description=f"Scanning directory & Git history: {target}...", total=None)
                findings = scan_directory(target, scan_git_history=scan_git_history)
            else:
                console.print(f"[bold red]Error:[/] Target path '{target}' is not a valid file, folder, or remote URL.")
                sys.exit(1)
    except Exception as e:
        console.print(f"[bold red]Scan failed with error:[/] {str(e)}")
        sys.exit(1)
        
    # 2. Audit gitignore
    gitignore_unignored = []
    if os.path.isdir(target) and not args.github and not args.zip:
        gitignore_unignored = audit_gitignore(target)
        
    # 3. Aggregate metrics
    risk_summary = calculate_security_score(findings)
    unique_findings, _ = detect_duplicates(findings)
    
    # 4. Generate report if specified
    if args.format != "console":
        if not args.output_file:
            # Generate default output name
            ext_map = {"json": ".json", "csv": ".csv", "markdown": ".md", "sarif": ".sarif", "html": ".html"}
            args.output_file = f"sentinel_report{ext_map[args.format]}"
            
        with console.status(f"[bold purple]Generating {args.format.upper()} report to {args.output_file}...[/]"):
            if args.format == "json":
                from sentinel_scan.reports.json_report import generate_json_report
                generate_json_report(findings, risk_summary, gitignore_unignored, args.output_file)
            elif args.format == "csv":
                from sentinel_scan.reports.csv_report import generate_csv_report
                generate_csv_report(findings, args.output_file)
            elif args.format == "markdown":
                from sentinel_scan.reports.markdown_report import generate_markdown_report
                generate_markdown_report(findings, risk_summary, gitignore_unignored, args.output_file)
            elif args.format == "sarif":
                from sentinel_scan.reports.sarif_report import generate_sarif_report
                generate_sarif_report(findings, args.output_file)
            elif args.format == "html":
                from sentinel_scan.reports.html_report import generate_html_report
                generate_html_report(findings, risk_summary, gitignore_unignored, args.output_file)
                
        console.print(f"\n[bold green]Success![/] Report saved to [purple]{args.output_file}[/].\n")
        
    # 5. Display Console results
    # Print the findings table
    if findings:
        console.print(f"\n[bold red]⚠️  DETECTED LEAKS ({len(findings)} total / {len(unique_findings)} unique):[/]\n")
        table = Table(border_style="purple")
        table.add_column("Secret Type", style="cyan")
        table.add_column("Severity")
        table.add_column("File Path", style="dim")
        table.add_column("Line:Col", style="magenta")
        table.add_column("Masked Secret", style="green")
        table.add_column("Source", style="blue")
        
        for fnd in findings:
            coords = f"{fnd.get('line_number', 'N/A')}:{fnd.get('start_column', 'N/A')}"
            source = "Commit History" if fnd.get("in_history") else "Active File"
            
            table.add_row(
                fnd.get("rule_name", ""),
                format_severity(fnd.get("severity", "MEDIUM")),
                fnd.get("file_path", ""),
                coords,
                mask_secret(fnd.get("secret", "")),
                source
            )
            
        console.print(table)
        
        # Detail / Explain mode
        if args.explain:
            console.print("\n[bold purple]🔍 EXPLANATIONS & REMEDIATION REMARKS:[/]\n")
            for idx, fnd in enumerate(findings, start=1):
                # Retrieve explanation
                expl_res = get_ai_explanation(fnd)
                console.print(f"[bold cyan]{idx}. {fnd.get('rule_name')} ({fnd.get('severity')})[/]")
                console.print(f"   [dim]Location: {fnd.get('file_path')}:{fnd.get('line_number')}[/]")
                console.print(f"   [yellow]Masked Secret: {mask_secret(fnd.get('secret'))}[/]")
                
                # Show Code Context
                if fnd.get("line_content"):
                    console.print(f"   [bold grey50]Context:[/] [mono]{fnd.get('line_content')}[/]")
                    
                panel_text = f"Explanation source: [purple]{expl_res['provider']}[/]\n\n{expl_res['explanation']}"
                console.print(Panel(panel_text, border_style="grey30", expand=False))
                console.print()
                
    else:
        console.print("[bold green]✅ Clean scan! No secrets detected in active files or history.[/]\n")
        
    # Print Gitignore warnings
    if gitignore_unignored:
        console.print("[bold orange1]⚠️  .gitignore Warning:[/] The following sensitive files exist in the project but are NOT ignored:")
        for path in gitignore_unignored:
            console.print(f"  - [red]{path}[/]")
        console.print("  [bold white]Fix this instantly by running:[/] [purple]python sentinel.py fix gitignore[/]\n")
        
    # Display the summary posture card
    print_summary_panel(risk_summary)
    
    # 6. Apply severity gate exit status
    if args.severity_gate:
        gate_severities = [s.upper().strip() for s in args.severity_gate.split(",")]
        triggered = [f for f in findings if f.get("severity", "MEDIUM").upper() in gate_severities]
        if triggered:
            console.print(f"\n[bold red]Severity gate failed:[/] Found {len(triggered)} secrets matching severities {args.severity_gate}.")
            sys.exit(1)

def run_gitignore_fix():
    root = "."
    unignored = audit_gitignore(root)
    if not unignored:
        console.print("[bold green]✅ Clean gitignore audit. No unignored files found.[/]")
        return
        
    console.print(f"Found {len(unignored)} unignored sensitive files.")
    success, msg = fix_gitignore(root, unignored)
    if success:
        console.print(f"[bold green]Success:[/] {msg}")
    else:
        console.print(f"[bold red]Failed:[/] {msg}")

def run_install_hook():
    success, msg = install_pre_commit_hook(".")
    if success:
        console.print(f"[bold green]Success:[/] {msg}")
    else:
        console.print(f"[bold red]Failed:[/] {msg}")

def run_export_ci():
    success, msg = export_github_action(".")
    if success:
        console.print(f"[bold green]Success:[/] {msg}")
    else:
        console.print(f"[bold red]Failed:[/] {msg}")

def run_compare(snapshot_path: str, current_target: str):
    console.print(f"Scanning target '{current_target}' to compare against snapshot '{snapshot_path}'...")
    
    # Scan target directory
    findings = []
    if os.path.isdir(current_target):
        findings = scan_directory(current_target, scan_git_history=True)
    elif os.path.isfile(current_target):
        findings = scan_file(current_target)
        
    comp = compare_snapshots(snapshot_path, findings)
    
    if "error" in comp:
        console.print(f"[bold red]Error:[/] {comp['error']}")
        sys.exit(1)
        
    summary = comp["comparison_summary"]
    console.print(f"\n[bold white]Comparison Summary:[/]")
    console.print(f"🟢 Resolved Secrets : [green]{summary['resolved_count']}[/]")
    console.print(f"🔴 New Secrets      : [red]{summary['new_count']}[/]")
    console.print(f"⚪ Unchanged Secrets : [grey50]{summary['unchanged_count']}[/]\n")
    
    if comp["new"]:
        console.print("[bold red]🚨 NEW SECRETS INTRODUCED SINCE SNAPSHOT:[/]")
        table = Table(border_style="red")
        table.add_column("Secret Type")
        table.add_column("Severity")
        table.add_column("File Path")
        table.add_column("Line:Col")
        table.add_column("Masked Secret")
        
        for f in comp["new"]:
            table.add_row(
                f.get("rule_name", ""),
                format_severity(f.get("severity", "MEDIUM")),
                f.get("file_path", ""),
                f"{f.get('line_number', 'N/A')}:{f.get('start_column', 'N/A')}",
                mask_secret(f.get("secret", ""))
            )
        console.print(table)
        
    if comp["resolved"]:
        console.print("[bold green]✅ SECRETS RESOLVED (CLEANED UP) SINCE SNAPSHOT:[/]")
        table = Table(border_style="green")
        table.add_column("Secret Type")
        table.add_column("Severity")
        table.add_column("File Path")
        
        for f in comp["resolved"]:
            table.add_row(
                f.get("rule_name", ""),
                format_severity(f.get("severity", "MEDIUM")),
                f.get("file_path", "")
            )
        console.print(table)
        
    if not comp["new"] and not comp["resolved"]:
        console.print("[bold green]No differences found. The codebase is identical in secret findings to the snapshot.[/]")

def run_watch_mode(target_dir: str):
    console.print(f"\n[bold green]👁️  Watch Mode Active:[/] Monitoring '[purple]{target_dir}[/]' for modifications... (Ctrl+C to quit)\n")
    
    def on_file_change_callback(file_path: str):
        rel_path = os.path.relpath(file_path, target_dir)
        console.print(f"[bold slate_blue]Change detected in:[/] [white]{rel_path}[/] ... Scanning...")
        
        findings = scan_file(file_path, root_dir=target_dir)
        
        if findings:
            console.print(f"[bold red]🚨 Alert:[/] Found {len(findings)} secrets in modified file!")
            table = Table(border_style="red")
            table.add_column("Secret Type")
            table.add_column("Severity")
            table.add_column("Line:Col")
            table.add_column("Masked Secret")
            
            for f in findings:
                table.add_row(
                    f.get("rule_name"),
                    format_severity(f.get("severity")),
                    f"{f.get('line_number')}:{f.get('start_column')}",
                    mask_secret(f.get("secret"))
                )
            console.print(table)
            console.print()
        else:
            console.print("[green]✔ Clean modification.[/]\n")
            
    from sentinel_scan.core.watch import start_watch_mode
    try:
        start_watch_mode(target_dir, on_file_change_callback)
    except Exception as e:
        console.print(f"[bold red]Watch mode stopped with error:[/] {str(e)}")
