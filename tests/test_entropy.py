import math
import pytest
from sentinel_scan.detectors.entropy import calculate_shannon_entropy, scan_text_for_entropy

def test_calculate_shannon_entropy_empty():
    assert calculate_shannon_entropy("") == 0.0

def test_calculate_shannon_entropy_uniform():
    # String of uniform characters has 0 entropy
    assert calculate_shannon_entropy("aaaaaaa") == 0.0
    assert calculate_shannon_entropy("1111111111") == 0.0

def test_calculate_shannon_entropy_calculation():
    # 'abcd' has 4 distinct characters, each p=0.25
    # Entropy = -4 * (0.25 * log2(0.25)) = -4 * (0.25 * -2) = 2.0
    assert abs(calculate_shannon_entropy("abcd") - 2.0) < 1e-9

def test_scan_text_for_entropy_ignores_excludes():
    # Excluded keywords shouldn't trigger entropy alerts
    text = "const myVariable = 'javascript';"
    findings = scan_text_for_entropy(text)
    assert len(findings) == 0

def test_scan_text_for_entropy_repeating():
    # Repeating sequences should be skipped
    text = "my_token = 'zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz';"
    findings = scan_text_for_entropy(text)
    assert len(findings) == 0

def test_scan_text_for_entropy_detects_secrets():
    # High entropy token containing both letters and digits should be detected
    # Example token: aB3dF6hJ9kL2nP5qR8sU1vW4yZ7 (27 characters)
    token = "aB3dF6hJ9kL2nP5qR8sU1vW4yZ7"
    text = f"api_key = '{token}'"
    findings = scan_text_for_entropy(text, threshold=3.5)
    assert len(findings) == 1
    assert findings[0]["secret"] == token
    assert findings[0]["rule_id"] == "high-entropy-secret"

def test_scan_text_for_entropy_threshold_filters():
    # With a high threshold, a lower-entropy string should be skipped
    token = "aB3dF6hJ9kL2nP5q" # 16 characters
    text = f"key = '{token}'"
    # Scanner adds 0.3 to threshold for strings shorter than 20 chars
    findings_high = scan_text_for_entropy(text, threshold=6.0)
    assert len(findings_high) == 0
