from sentinel_scan.core.rules import check_regex_match, SECRET_RULES

def test_rule_aws_access_key():
    text = "aws_key = 'AKIAIOSFODNN7EXAMPLE'"
    findings = check_regex_match(text)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "aws-access-key"
    assert findings[0]["secret"] == "AKIAIOSFODNN7EXAMPLE"

def test_rule_aws_secret_key():
    text = "aws_secret = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'"
    # Wait, the secret key regex is: (?i)aws_(?:secret_)?(?:access_)?(?:key|secret)(?:[\"']?\s*[:=]\s*[\"']?)([A-Za-z0-9/+=]{40})
    # Let's test matches
    text = "aws_secret_access_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'"
    findings = check_regex_match(text)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "aws-secret-key"
    assert findings[0]["secret"] == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

def test_rule_gcp_api_key():
    text = "const apiKey = 'AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q';"
    findings = check_regex_match(text)
    assert len(findings) == 2
    rule_ids = [f["rule_id"] for f in findings]
    assert "gcp-api-key" in rule_ids
    assert "gemini-api-key" in rule_ids

def test_rule_openai_api_key():
    # OpenAI: sk-proj-1234... or sk-...
    text = "openai.api_key = 'sk-proj-U7d6F5e4D3c2B1a0Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3'"
    findings = check_regex_match(text)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "openai-api-key"
    assert findings[0]["secret"] == "sk-proj-U7d6F5e4D3c2B1a0Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3"

def test_rule_mongodb_uri():
    text = "conn = 'mongodb://dbuser:mypassword123@cluster0.example.com:27017/mydb'"
    findings = check_regex_match(text)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "mongodb-uri"
    assert "mypassword123" in findings[0]["secret"]
