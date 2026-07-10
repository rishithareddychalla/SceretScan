import os
import tempfile
import shutil
from typing import List, Dict, Any, Optional
import git

def make_git_error_user_friendly(err_msg: str) -> str:
    """Translates noisy git clone commands/tracebacks into clean, user-friendly messages."""
    err_lower = err_msg.lower()
    
    if "repository" in err_lower and ("not found" in err_lower or "does not exist" in err_lower):
        return "Repository not found. Please verify that the repository URL is correct and that you have access to it."
    elif "authentication failed" in err_lower or "could not read username" in err_lower or "terminal prompts disabled" in err_lower:
        return "Authentication failed. Please verify that your username and access token/password are correct and have appropriate permissions."
    elif "could not resolve host" in err_lower:
        return "Could not connect to host. Please verify your internet connection and check if the domain is correct."
    elif "permission denied" in err_lower or "publickey" in err_lower:
        return "Permission denied (SSH/Key failure). If this is a private repository, please check your SSH keys or try cloning using HTTPS with username/token credentials."
    
    # Extract the last 'fatal:' or 'error:' message from git output
    import re
    fatal_matches = re.findall(r"(?:fatal|error):\s*([^\r\n']+)", err_msg, re.IGNORECASE)
    if fatal_matches:
        return fatal_matches[-1].strip()
        
    return "Failed to clone repository. Please check your network connection and credentials, and try again."

def clone_and_scan_github_repo(
    repo_url: str,
    github_token: Optional[str] = None,
    scan_history: bool = True,
    git_username: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Clones a remote Git repository (GitHub, GitLab, Bitbucket, etc.) into a temporary directory and scans it.
    Supports private repositories if a github_token / password is provided.
    """
    url = repo_url.strip()
    
    # Authenticate the URL if token is present
    if github_token:
        # Check if URL starts with https://
        if url.startswith("https://"):
            rest = url[len("https://"):]
            creds = f"{git_username}:{github_token}" if git_username else github_token
            url = f"https://{creds}@{rest}"
        elif url.startswith("http://"):
            rest = url[len("http://"):]
            creds = f"{git_username}:{github_token}" if git_username else github_token
            url = f"http://{creds}@{rest}"
        else:
            # Fallback insertion (e.g. github.com/owner/repo)
            creds = f"{git_username}:{github_token}" if git_username else github_token
            url = f"https://{creds}@{url}"
            
    # Create temp directory
    temp_dir = tempfile.mkdtemp(prefix="sentinel_scan_git_")
    
    findings = []
    try:
        # Clone repo
        clone_kwargs = {}
        if not scan_history:
            clone_kwargs["depth"] = 1
            
        repo = git.Repo.clone_from(url, temp_dir, **clone_kwargs)
        
        # Scan working directory
        from sentinel_scan.core.scanner import scan_directory
        findings = scan_directory(temp_dir, scan_git_history=scan_history)
        
        # Rewrite the absolute paths to represent the Git repo relative path
        for f in findings:
            abs_path = f.get("file_path", "")
            if abs_path.startswith(temp_dir):
                rel_path = os.path.relpath(abs_path, temp_dir).replace(os.path.sep, '/')
                f["file_path"] = rel_path
                
    except Exception as e:
        # Sanitize sensitive token/password from error message
        err_msg = str(e)
        if github_token:
            err_msg = err_msg.replace(github_token, "********")
        if repo_url:
            # Also mask password inside url structure in the error if any
            import re as regex
            err_msg = regex.sub(r'https://[^@]+@', 'https://********@', err_msg)
            err_msg = regex.sub(r'http://[^@]+@', 'http://********@', err_msg)
        
        user_friendly_msg = make_git_error_user_friendly(err_msg)
        raise Exception(f"Failed to clone repository: {user_friendly_msg}")
    finally:
        # Clean up temp dir
        try:
            shutil.rmtree(temp_dir, ignore_errors=True)
        except Exception:
            pass
            
    return findings
