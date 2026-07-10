import os
from typing import List, Dict, Any, Iterator
import git
from sentinel_scan.sources.file_source import DEFAULT_EXCLUDES, DEFAULT_EXCLUDE_EXTENSIONS

def is_binary_file(filename: str) -> bool:
    _, ext = os.path.splitext(filename)
    return ext.lower() in DEFAULT_EXCLUDE_EXTENSIONS

def get_git_history_findings(repo_path: str) -> List[Dict[str, Any]]:
    """
    Iterates through the entire Git commit history of the repository,
    analyzing added lines in diffs for secrets.
    """
    findings = []
    
    if not os.path.exists(os.path.join(repo_path, ".git")):
        return findings
        
    try:
        repo = git.Repo(repo_path)
    except Exception as e:
        # Not a valid git repo or git not installed
        return findings
        
    # Import scanning functions dynamically to avoid circular dependencies
    from sentinel_scan.core.rules import check_regex_match
    from sentinel_scan.detectors.entropy import scan_text_for_entropy
    
    seen_commit_secrets = set() # Avoid reporting same secret multiple times in same commit
    
    # Iterate commits in reverse order (oldest to newest) to trace timeline
    try:
        commits = list(repo.iter_commits())
        commits.reverse() # Start from first commit
    except Exception:
        return findings
        
    for commit in commits:
        commit_hash = commit.hexsha
        author = commit.author.name
        email = commit.author.email
        date_str = commit.committed_datetime.isoformat()
        message = commit.message.strip()
        
        # Get diffs for this commit. If no parent, diff against empty tree
        parent = commit.parents[0] if commit.parents else None
        diffs = commit.diff(parent, create_patch=True)
        
        for d in diffs:
            # We only care about added/modified content
            # d.a_path is old path, d.b_path is new path. If d.new_file is true, a_path is None.
            file_path = d.b_path or d.a_path
            if not file_path:
                continue
                
            # Skip if path is in excludes or is binary
            parts = file_path.replace('\\', '/').split('/')
            if any(part in DEFAULT_EXCLUDES for part in parts):
                continue
            if is_binary_file(file_path):
                continue
                
            # Parse the diff patch to extract newly added lines
            diff_text = ""
            try:
                if d.diff:
                    diff_text = d.diff.decode('utf-8', errors='surrogateescape')
            except Exception:
                continue
                
            if not diff_text:
                continue
                
            # Extract added lines (lines starting with + but not +++)
            added_lines = []
            line_num = 0
            for line in diff_text.splitlines():
                if line.startswith('+++'):
                    continue
                if line.startswith('+'):
                    added_lines.append((line_num, line[1:]))
                # Count line numbers inside patch (approximate for reporting)
                if not line.startswith('-'):
                    line_num += 1
                    
            # Combine added lines and scan them
            # For accurate line scanning, we scan each added line individually
            for local_line_num, line_content in added_lines:
                # Run regex matches
                regex_hits = check_regex_match(line_content)
                # Run entropy matches
                entropy_hits = scan_text_for_entropy(line_content)
                
                all_hits = regex_hits + entropy_hits
                
                for hit in all_hits:
                    secret_val = hit["secret"]
                    # Dedup identical findings in the same commit/file
                    dedup_key = f"{commit_hash}:{file_path}:{secret_val}"
                    if dedup_key in seen_commit_secrets:
                        continue
                    seen_commit_secrets.add(dedup_key)
                    
                    findings.append({
                        "rule_id": hit["rule_id"],
                        "rule_name": hit["rule_name"],
                        "severity": hit["severity"],
                        "category": hit["category"],
                        "secret": secret_val,
                        "description": hit["description"],
                        "remediation": hit["remediation"],
                        "file_path": file_path,
                        "line_number": local_line_num, # Local diff offset
                        "line_content": line_content.strip(),
                        "commit_hash": commit_hash,
                        "commit_author": f"{author} <{email}>",
                        "commit_date": date_str,
                        "commit_message": message,
                        "in_history": True
                    })
                    
    return findings
