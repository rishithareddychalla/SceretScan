import os
import stat
from typing import List, Dict, Any, Tuple
from sentinel_scan.sources.file_source import GitIgnoreParser

# File patterns that are considered sensitive and should be gitignored
SENSITIVE_FILES = [
    ".env",
    ".env.local",
    ".env.development",
    ".env.production",
    "secrets.json",
    "credentials.json",
    "config.json",
    "appsettings.json",
    "*.pem",
    "*.key",
    "id_rsa",
    "id_ecdsa",
    "id_ed25519"
]

def audit_gitignore(root_dir: str) -> List[str]:
    """
    Audits the workspace for sensitive files that exist but are NOT ignored by .gitignore.
    Returns a list of unignored sensitive file paths.
    """
    parser = GitIgnoreParser(root_dir)
    unignored_sensitive_files = []
    
    # We walk the directory and look for sensitive files specifically
    for dirpath, _, filenames in os.walk(root_dir):
        # Skip git directories
        if ".git" in dirpath.split(os.path.sep):
            continue
            
        for filename in filenames:
            file_path = os.path.join(dirpath, filename)
            rel_path = os.path.relpath(file_path, root_dir)
            
            # Check if this filename matches any of our sensitive patterns
            is_sensitive = False
            for pattern in SENSITIVE_FILES:
                if pattern.startswith("*."):
                    ext = pattern[1:]
                    if filename.endswith(ext):
                        is_sensitive = True
                        break
                elif filename == pattern:
                    is_sensitive = True
                    break
                    
            if is_sensitive:
                # Check if it's ignored by .gitignore
                if not parser.is_ignored(file_path):
                    unignored_sensitive_files.append(rel_path.replace(os.path.sep, '/'))
                    
    return unignored_sensitive_files

def fix_gitignore(root_dir: str, files_to_ignore: List[str]) -> Tuple[bool, str]:
    """
    Appends files to .gitignore to make sure they are ignored.
    Creates .gitignore if it doesn't exist.
    """
    if not files_to_ignore:
        return False, "No sensitive files to ignore."
        
    gitignore_path = os.path.join(root_dir, ".gitignore")
    existing_content = ""
    if os.path.exists(gitignore_path):
        try:
            with open(gitignore_path, "r", encoding="utf-8") as f:
                existing_content = f.read()
        except Exception as e:
            return False, f"Failed to read existing .gitignore: {str(e)}"
            
    # Normalize ending newlines
    if existing_content and not existing_content.endswith("\n"):
        existing_content += "\n"
        
    lines_to_add = []
    for file in files_to_ignore:
        # Check if already present as literal string in file to avoid duplicate entries
        if file not in existing_content:
            lines_to_add.append(file)
            
    if not lines_to_add:
        return True, ".gitignore already ignores these files."
        
    try:
        with open(gitignore_path, "a", encoding="utf-8") as f:
            if not existing_content:
                f.write("# SentinelScan Security Ignores\n")
            else:
                f.write("\n# SentinelScan Security Ignores\n")
            for line in lines_to_add:
                f.write(f"{line}\n")
        return True, f"Successfully added {len(lines_to_add)} patterns to .gitignore."
    except Exception as e:
        return False, f"Failed to write to .gitignore: {str(e)}"

def install_pre_commit_hook(root_dir: str) -> Tuple[bool, str]:
    """
    Installs a Git pre-commit hook in the repository.
    The hook runs SentinelScan before commits and blocks them if critical secrets are found.
    """
    git_dir = os.path.join(root_dir, ".git")
    if not os.path.exists(git_dir):
        return False, "Not a Git repository. Cannot install pre-commit hook."
        
    hooks_dir = os.path.join(git_dir, "hooks")
    os.makedirs(hooks_dir, exist_ok=True)
    
    hook_path = os.path.join(hooks_dir, "pre-commit")
    
    # Pre-commit hook script (Shell script, works on git-bash for Windows, and macOS/Linux)
    hook_script = """#!/bin/sh
# SentinelScan Git Pre-Commit Hook
# Prevents committing secrets.

echo "🛡️  Running SentinelScan pre-commit hook..."

# Run scanning command on the staged files (or full workspace)
# We exit with non-zero if critical or high secrets are found.
python sentinel.py scan . --severity-gate CRITICAL,HIGH

STATUS=$?

if [ $STATUS -ne 0 ]; then
    echo "❌ [SentinelScan] Commit blocked: Critical or High severity secrets detected!"
    echo "Please review the findings, remove the secrets, and try again."
    exit 1
fi

echo "✅ [SentinelScan] Clean scan. Proceeding with commit."
exit 0
"""
    
    try:
        with open(hook_path, "w", newline="\n", encoding="utf-8") as f:
            f.write(hook_script)
            
        # Make script executable (chmod +x)
        # On Windows this is a no-op but we still try it for POSIX compatibility
        st = os.stat(hook_path)
        os.chmod(hook_path, st.st_mode | stat.S_IEXEC)
        
        return True, "Pre-commit hook successfully installed at .git/hooks/pre-commit"
    except Exception as e:
        return False, f"Failed to install pre-commit hook: {str(e)}"
