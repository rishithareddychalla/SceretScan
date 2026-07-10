from sentinel_scan.sources.github_source import make_git_error_user_friendly
from web_ui import make_error_user_friendly
import zipfile

def test_make_git_error_user_friendly():
    # Test repo not found
    err1 = "Cmd('git') failed due to: exit code(128)\n  cmdline: git clone ...\n  stderr: 'fatal: repository https://github.com/nonexistent/repo not found'"
    assert "Repository not found" in make_git_error_user_friendly(err1)
    
    # Test auth failure
    err2 = "fatal: Authentication failed for 'https://github.com/some/private-repo.git'"
    assert "Authentication failed" in make_git_error_user_friendly(err2)
    
    # Test host resolution
    err3 = "fatal: Could not resolve host: github.com"
    assert "Could not connect to host" in make_git_error_user_friendly(err3)
    
    # Test other fatal errors (extract last line)
    err4 = "random trace\nfatal: some other strange git error here"
    assert make_git_error_user_friendly(err4) == "some other strange git error here"

def test_make_error_user_friendly():
    # Test BadZipFile
    bz = zipfile.BadZipFile("File is not a zip file")
    assert "not a valid ZIP archive" in make_error_user_friendly(bz)
    
    # Test PermissionError
    pe = PermissionError("[Errno 13] Permission denied: 'secret.txt'")
    assert "Permission denied" in make_error_user_friendly(pe)
    
    # Test FileNotFoundError
    fnf = FileNotFoundError("[Errno 2] No such file or directory: 'missing.txt'")
    assert "File or directory not found" in make_error_user_friendly(fnf)
