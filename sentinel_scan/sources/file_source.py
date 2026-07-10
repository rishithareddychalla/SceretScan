import os
import re
from typing import List, Set, Iterator

# Default patterns/folders to ignore during local scans
DEFAULT_EXCLUDES = {
    '.git',
    '.github',
    'node_modules',
    'bower_components',
    '.venv',
    'venv',
    'env',
    '.gradle',
    '.idea',
    '.vscode',
    '__pycache__',
    '.pytest_cache',
    '.mypy_cache',
    'build',
    'dist',
    'target',
    'out',
    'vendor'
}

DEFAULT_EXCLUDE_EXTENSIONS = {
    '.png', '.jpg', '.jpeg', '.gif', '.ico', '.zip', '.tar', '.gz', '.7z',
    '.rar', '.exe', '.dll', '.so', '.dylib', '.bin', '.woff', '.woff2', '.eot',
    '.ttf', '.mp4', '.mp3', '.wav', '.avi', '.mov', '.flv', '.ogg', '.webm',
    '.db', '.sqlite', '.sqlite3', '.pyc', '.class', '.o', '.a', '.lib'
}

DEFAULT_EXCLUDE_FILENAMES = {
    'report.json', 'report.csv', 'report.md', 'report.sarif', 'report.html',
    'sentinel_report.json', 'sentinel_report.csv', 'sentinel_report.md', 'sentinel_report.sarif', 'sentinel_report.html',
    'snapshot.json'
}

class GitIgnoreParser:
    """A simple parser for .gitignore files to respect repository exclusion rules."""
    def __init__(self, root_dir: str):
        self.root_dir = os.path.abspath(root_dir)
        self.patterns: List[str] = []
        
        gitignore_path = os.path.join(self.root_dir, ".gitignore")
        if os.path.exists(gitignore_path):
            try:
                with open(gitignore_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        self.patterns.append(line)
            except Exception:
                pass

    def is_ignored(self, file_path: str) -> bool:
        """Determines if a given file path matches any .gitignore pattern."""
        abs_path = os.path.abspath(file_path)
        # Get path relative to the gitignore root
        try:
            rel_path = os.path.relpath(abs_path, self.root_dir).replace(os.path.sep, '/')
        except ValueError:
            return False
            
        for pattern in self.patterns:
            # Simple gitignore matching logic
            # Handle directory trailing slash
            pat = pattern
            is_dir_only = pat.endswith('/')
            if is_dir_only:
                pat = pat[:-1]
                
            # Convert glob to regex
            # Escape regex chars except * and ?
            reg_pat = re.escape(pat).replace(r'\*', '.*').replace(r'\?', '.')
            
            # Match anywhere or match from root
            if pattern.startswith('/'):
                reg_pat = '^' + reg_pat[1:]
            else:
                reg_pat = '(^|/)' + reg_pat
                
            if is_dir_only:
                reg_pat += '/.*'
            else:
                reg_pat += '($|/)'
                
            try:
                if re.search(reg_pat, rel_path):
                    return True
            except re.error:
                continue
        return False

def get_all_files(root_dir: str, use_gitignore: bool = True) -> Iterator[str]:
    """Recursively lists all files in a directory, respecting default excludes and .gitignore."""
    gitignore_parser = GitIgnoreParser(root_dir) if use_gitignore else None
    
    for dirpath, dirnames, filenames in os.walk(root_dir):
        # Modify dirnames in-place to skip excluded directories
        dirnames[:] = [d for d in dirnames if d not in DEFAULT_EXCLUDES]
        
        for filename in filenames:
            file_path = os.path.join(dirpath, filename)
            
            # Skip by filename
            if filename.lower() in DEFAULT_EXCLUDE_FILENAMES:
                continue
                
            # Skip by extension
            _, ext = os.path.splitext(filename)
            if ext.lower() in DEFAULT_EXCLUDE_EXTENSIONS:
                continue
                
            # Skip by gitignore
            if gitignore_parser and gitignore_parser.is_ignored(file_path):
                continue
                
            yield file_path

def read_docx(file_path: str) -> str:
    """Reads a DOCX file and extracts all text content."""
    import zipfile
    import xml.etree.ElementTree as ET
    try:
        with zipfile.ZipFile(file_path) as z:
            xml_content = z.read('word/document.xml')
            root = ET.fromstring(xml_content)
            texts = []
            for elem in root.iter():
                tag_lower = elem.tag.lower()
                if tag_lower.endswith('}t') or tag_lower.endswith(':t') or tag_lower == 't':
                    if elem.text:
                        texts.append(elem.text)
            return " ".join(texts)
    except Exception:
        return ""

def read_xlsx(file_path: str) -> str:
    """Reads an XLSX file and extracts text values."""
    import zipfile
    import xml.etree.ElementTree as ET
    try:
        texts = []
        with zipfile.ZipFile(file_path) as z:
            if 'xl/sharedStrings.xml' in z.namelist():
                xml_content = z.read('xl/sharedStrings.xml')
                root = ET.fromstring(xml_content)
                for elem in root.iter():
                    tag_lower = elem.tag.lower()
                    if tag_lower.endswith('}t') or tag_lower.endswith(':t') or tag_lower == 't':
                        if elem.text:
                            texts.append(elem.text)
            for name in z.namelist():
                if name.startswith('xl/worksheets/sheet') and name.endswith('.xml'):
                    xml_content = z.read(name)
                    root = ET.fromstring(xml_content)
                    for elem in root.iter():
                        tag_lower = elem.tag.lower()
                        if tag_lower.endswith('}v') or tag_lower.endswith(':v') or tag_lower == 'v':
                            if elem.text:
                                texts.append(elem.text)
        return "\n".join(texts)
    except Exception:
        return ""

def read_pptx(file_path: str) -> str:
    """Reads a PPTX file and extracts text values from slides."""
    import zipfile
    import xml.etree.ElementTree as ET
    try:
        texts = []
        with zipfile.ZipFile(file_path) as z:
            for name in z.namelist():
                if name.startswith('ppt/slides/slide') and name.endswith('.xml'):
                    xml_content = z.read(name)
                    root = ET.fromstring(xml_content)
                    for elem in root.iter():
                        tag_lower = elem.tag.lower()
                        if tag_lower.endswith('}t') or tag_lower.endswith(':t') or tag_lower == 't':
                            if elem.text:
                                texts.append(elem.text)
        return "\n".join(texts)
    except Exception:
        return ""

def read_odt(file_path: str) -> str:
    """Reads an ODT file and extracts text content."""
    import zipfile
    import xml.etree.ElementTree as ET
    try:
        with zipfile.ZipFile(file_path) as z:
            xml_content = z.read('content.xml')
            root = ET.fromstring(xml_content)
            texts = []
            for elem in root.iter():
                tag_lower = elem.tag.lower()
                if tag_lower.endswith('}text') or tag_lower.endswith('}p') or tag_lower.endswith(':text') or tag_lower.endswith(':p') or tag_lower in ('text', 'p'):
                    if elem.text:
                        texts.append(elem.text)
                    if elem.tail:
                        texts.append(elem.tail)
            return " ".join(texts)
    except Exception:
        return ""

def read_rtf(file_path: str) -> str:
    """Reads an RTF file and strips formatting codes."""
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        content = re.sub(r'\\[a-z0-9*-]+', ' ', content)
        content = re.sub(r'[{}]', ' ', content)
        content = re.sub(r'\s+', ' ', content)
        return content.strip()
    except Exception:
        return ""

def read_binary_strings(file_path: str) -> str:
    """Extracts printable ASCII and UTF-16 strings from binary files as a fallback."""
    try:
        with open(file_path, "rb") as f:
            data = f.read()
        ascii_strings = re.findall(rb'[ -~]{4,}', data)
        utf16_strings = re.findall(rb'(?:[\x20-\x7E]\x00){4,}', data)
        decoded = []
        for s in ascii_strings:
            try:
                decoded.append(s.decode('ascii'))
            except Exception:
                pass
        for s in utf16_strings:
            try:
                decoded.append(s.decode('utf-16le'))
            except Exception:
                pass
        return "\n".join(decoded)
    except Exception:
        return ""

def read_file_safe(file_path: str) -> str:
    """Reads a file securely, handling encoding issues and returning content."""
    ext = file_path.lower()
    
    # Check if PDF
    if ext.endswith(".pdf"):
        try:
            import pypdf
            reader = pypdf.PdfReader(file_path)
            text_parts = []
            for page in reader.pages:
                t = page.extract_text()
                if t:
                    text_parts.append(t)
            return "\n".join(text_parts)
        except Exception:
            return ""
            
    # Check if DOCX
    elif ext.endswith(".docx"):
        return read_docx(file_path)
        
    # Check if XLSX
    elif ext.endswith(".xlsx"):
        return read_xlsx(file_path)
        
    # Check if PPTX
    elif ext.endswith(".pptx"):
        return read_pptx(file_path)
        
    # Check if ODT
    elif ext.endswith(".odt"):
        return read_odt(file_path)
        
    # Check if RTF
    elif ext.endswith(".rtf"):
        return read_rtf(file_path)
        
    # Check if old DOC or XLS or any binary
    elif ext.endswith((".doc", ".xls", ".ppt", ".bin", ".exe", ".dll", ".so")):
        return read_binary_strings(file_path)

    try:
        # Try UTF-8 first
        with open(file_path, "r", encoding="utf-8", errors="surrogateescape") as f:
            return f.read()
    except Exception:
        # Fallback to latin-1
        try:
            with open(file_path, "r", encoding="latin-1") as f:
                return f.read()
        except Exception:
            # Final fallback: read as binary strings
            return read_binary_strings(file_path)
