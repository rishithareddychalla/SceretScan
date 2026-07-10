import math
import re
from typing import List, Dict, Any

def calculate_shannon_entropy(data: str) -> float:
    """Calculates the Shannon entropy of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    # Count occurrences of each character
    char_counts = {}
    for char in data:
        char_counts[char] = char_counts.get(char, 0) + 1
    # Calculate Shannon entropy
    for count in char_counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

# Matches potential secret candidate strings (alphanumeric, plus some common key symbols)
# of length 16 to 128.
SECRET_CANDIDATE_REGEX = re.compile(r'\b[A-Za-z0-9+/=_-]{16,128}\b')

# Words to ignore for entropy detection (common programming terms, types, etc.)
EXCLUDE_WORDS = {
    'true', 'false', 'boolean', 'string', 'integer', 'nullable', 'undefined', 'null',
    'import', 'export', 'require', 'const', 'function', 'class', 'public', 'private',
    'protected', 'default', 'return', 'extends', 'implements', 'interface', 'package',
    'namespace', 'using', 'stdcall', 'declspec', 'thread_local', 'constexpr', 'alignas',
    'static_cast', 'dynamic_cast', 'reinterpret_cast', 'const_cast', 'typeid', 'template',
    'typename', 'virtual', 'override', 'final', 'noexcept', 'volatile', 'mutable',
    'explicit', 'operator', 'unsigned', 'signed', 'long', 'short', 'double', 'float',
    'javascript', 'typescript', 'python', 'application', 'configuration', 'development'
}

def scan_text_for_entropy(text: str, threshold: float = 4.5) -> List[Dict[str, Any]]:
    """
    Scans text for strings with high Shannon entropy, suggesting random keys/secrets.
    Returns findings with details about coordinates and secret value.
    """
    findings = []
    lines = text.splitlines()
    
    for line_num, line_content in enumerate(lines, start=1):
        # Find all candidate tokens in the line
        for match in SECRET_CANDIDATE_REGEX.finditer(line_content):
            token = match.group(0)
            
            # Check length, and skip if it matches common exclude words
            if len(token) < 20:  # Higher threshold for purely random keys
                current_threshold = threshold + 0.3
            else:
                current_threshold = threshold
                
            if token.lower() in EXCLUDE_WORDS:
                continue
                
            # Skip if it is a repeating sequence of characters (e.g. "aaaaaaaaaaaaaaaaaaaa")
            if len(set(token)) <= 4:
                continue
                
            # Skip if it contains too many punctuation marks or looks like a file path
            if '/' in token and (token.startswith('/') or token.endswith('/') or token.count('/') > 2):
                continue
                
            # Calculate entropy
            entropy = calculate_shannon_entropy(token)
            
            if entropy >= current_threshold:
                # To reduce false positives, check if it contains a mix of digits, lowercase, and uppercase letters
                has_digit = any(c.isdigit() for c in token)
                has_lower = any(c.islower() for c in token)
                has_upper = any(c.isupper() for c in token)
                
                # A high-entropy key usually has digits and letters
                if not (has_digit and (has_lower or has_upper)):
                    continue
                
                findings.append({
                    "rule_id": "high-entropy-secret",
                    "rule_name": f"High Entropy Secret (Entropy: {entropy:.2f})",
                    "severity": "HIGH" if entropy >= 5.0 else "MEDIUM",
                    "category": "High Entropy Secret",
                    "secret": token,
                    "description": f"A string with high Shannon entropy ({entropy:.2f}) was detected. This typically indicates an API key, private key, token, or password.",
                    "remediation": "Investigate if this string is a hardcoded secret. If so, rotate the secret and remove it from the code, placing it in a secure environment configuration.",
                    "line_number": line_num,
                    "start_column": match.start() + 1,
                    "end_column": match.end() + 1,
                    "line_content": line_content.strip()
                })
                
    return findings
