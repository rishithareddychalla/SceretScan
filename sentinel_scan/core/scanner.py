import os
import concurrent.futures
from typing import List, Dict, Any, Optional
from sentinel_scan.core.rules import check_regex_match
from sentinel_scan.detectors.entropy import scan_text_for_entropy
from sentinel_scan.sources.file_source import get_all_files, read_file_safe
from sentinel_scan.sources.zip_source import get_zip_files
from sentinel_scan.sources.git_source import get_git_history_findings

def scan_file(
    file_path: str, 
    root_dir: Optional[str] = None,
    config: Optional[Dict[str, Any]] = None
) -> List[Dict[str, Any]]:
    """Scans a single file for regex patterns and high entropy secrets."""
    findings = []
    
    # Read file content safely
    content = read_file_safe(file_path)
    if not content:
        return findings
        
    # Get display path (relative to root if provided)
    display_path = file_path
    if root_dir:
        try:
            display_path = os.path.relpath(file_path, root_dir).replace(os.path.sep, '/')
        except ValueError:
            pass
            
    # Extract config parameters
    entropy_threshold = 4.5
    disabled_rules = []
    if config:
        entropy_threshold = config.get("entropy_threshold", 4.5)
        disabled_rules = config.get("disabled_rules", [])

    # Run regex matching
    regex_findings = check_regex_match(content)
    
    # Run entropy scanning
    entropy_findings = scan_text_for_entropy(content, threshold=entropy_threshold)
    
    # Merge findings
    all_findings = regex_findings + entropy_findings
    
    # Enrich findings with file metadata and filter disabled rules
    for f in all_findings:
        if f.get("rule_id") in disabled_rules:
            continue
        f["file_path"] = display_path
        f["in_history"] = False
        findings.append(f)
        
    return findings

def scan_directory(
    dir_path: str,
    scan_git_history: bool = True,
    use_gitignore: bool = True,
    max_workers: int = 4,
    config: Optional[Dict[str, Any]] = None
) -> List[Dict[str, Any]]:
    """
    Scans an entire directory for secrets in parallel.
    Includes active workspace scanning and optionally Git history scanning.
    """
    abs_dir_path = os.path.abspath(dir_path)
    findings = []
    
    # 1. Get all files in directory (respecting excludes and .gitignore)
    file_paths = list(get_all_files(abs_dir_path, use_gitignore=use_gitignore))
    
    # 2. Scan files in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit tasks
        future_to_file = {
            executor.submit(scan_file, fp, abs_dir_path, config): fp for fp in file_paths
        }
        
        # Collect results
        for future in concurrent.futures.as_completed(future_to_file):
            file_findings = future.result()
            findings.extend(file_findings)
            
    # 3. Scan Git History if enabled
    if scan_git_history:
        git_history_findings = get_git_history_findings(abs_dir_path)
        # Filter disabled rules for history findings
        if config and "disabled_rules" in config:
            disabled = config["disabled_rules"]
            git_history_findings = [f for f in git_history_findings if f.get("rule_id") not in disabled]
        findings.extend(git_history_findings)
        
    return findings

def scan_zip_file(
    zip_path: str, 
    max_workers: int = 4,
    config: Optional[Dict[str, Any]] = None
) -> List[Dict[str, Any]]:
    """Scans all files inside a ZIP archive in parallel without extracting them to disk."""
    findings = []
    
    # Extract file list and contents
    zip_files = list(get_zip_files(zip_path))
    
    entropy_threshold = 4.5
    disabled_rules = []
    if config:
        entropy_threshold = config.get("entropy_threshold", 4.5)
        disabled_rules = config.get("disabled_rules", [])

    # Define a helper function to scan in-memory zip file
    def scan_in_memory_file(name: str, content: str) -> List[Dict[str, Any]]:
        file_findings = []
        
        regex_hits = check_regex_match(content)
        entropy_hits = scan_text_for_entropy(content, threshold=entropy_threshold)
        
        for hit in regex_hits + entropy_hits:
            if hit.get("rule_id") in disabled_rules:
                continue
            hit["file_path"] = f"{zip_path}::{name}"
            hit["in_history"] = False
            file_findings.append(hit)
            
        return file_findings

    # Scan in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_zipfile = {
            executor.submit(scan_in_memory_file, name, content): name
            for name, content in zip_files
        }
        
        for future in concurrent.futures.as_completed(future_to_zipfile):
            file_findings = future.result()
            findings.extend(file_findings)
            
    return findings
