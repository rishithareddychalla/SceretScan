import re
from typing import List, Optional, Dict, Any

class Rule:
    def __init__(
        self,
        rule_id: str,
        name: str,
        regex_pattern: str,
        severity: str,
        category: str,
        description: str,
        remediation: str,
        is_case_sensitive: bool = True
    ):
        self.rule_id = rule_id
        self.name = name
        self.regex_pattern = regex_pattern
        self.severity = severity  # CRITICAL, HIGH, MEDIUM, LOW
        self.category = category
        self.description = description
        self.remediation = remediation
        
        flags = 0 if is_case_sensitive else re.IGNORECASE
        self.regex = re.compile(regex_pattern, flags)

SECRET_RULES: List[Rule] = [
    # Private Keys
    Rule(
        rule_id="pem-private-key",
        name="PEM Private Key",
        regex_pattern=r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        severity="CRITICAL",
        category="Private Key",
        description="A private key (PEM/RSA/EC/DSA/OPENSSH) was detected. Anyone with access to this key can authenticate as the server/user.",
        remediation="Revoke the compromised private key immediately. Generate a new keypair and update the authorized keys list or client credentials. Ensure private keys are never committed to repositories."
    ),
    
    # AWS Credentials
    Rule(
        rule_id="aws-access-key",
        name="AWS Access Key ID",
        regex_pattern=r"\b(?:AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b",
        severity="HIGH",
        category="AWS Credentials",
        description="An AWS Access Key ID was detected. This identifies an AWS account or IAM user.",
        remediation="Check if this key is active in the AWS Console. If it is active, rotate the key immediately and deactivate/delete the compromised key. Utilize AWS Secrets Manager for secret management."
    ),
    Rule(
        rule_id="aws-secret-key",
        name="AWS Secret Access Key",
        regex_pattern=r"(?i)aws_(?:secret_)?(?:access_)?(?:key|secret)(?:[\"']?\s*[:=]\s*[\"']?)([A-Za-z0-9/+=]{40})",
        severity="CRITICAL",
        category="AWS Credentials",
        description="An AWS Secret Access Key was detected. When combined with an Access Key ID, this provides full access to AWS API operations.",
        remediation="Immediately deactivate and delete this credential from IAM. Check AWS CloudTrail logs for unauthorized API activity. Rotate all credentials that may have been accessed."
    ),

    # Google Cloud & Firebase
    Rule(
        rule_id="gcp-api-key",
        name="GCP/Firebase API Key",
        regex_pattern=r"\bAIza[0-9A-Za-z_-]{35}\b",
        severity="HIGH",
        category="GCP/Firebase",
        description="A Google Cloud Platform or Firebase API Key was detected. These keys authenticate requests to Google APIs.",
        remediation="Visit the Google Cloud Console (APIs & Services > Credentials), restrict the API key to specific HTTP referrers, IPs, or APIs, or rotate/delete it if it was leaked publicly."
    ),
    Rule(
        rule_id="gcp-service-account",
        name="GCP Service Account Private Key",
        regex_pattern=r"\"type\"\s*:\s*\"service_account\"|\"private_key_id\"\s*:\s*\"[a-f0-9]{40}\"",
        severity="CRITICAL",
        category="GCP/Firebase",
        description="A Google Cloud Platform Service Account JSON file/metadata was detected. This provides full administrative access to configured GCP resources.",
        remediation="Immediately revoke the service account key in the GCP Console under IAM & Admin > Service Accounts. Generate a new key and update your application config securely."
    ),

    # OpenAI / Gemini / Anthropic / Groq / OpenRouter
    Rule(
        rule_id="openai-api-key",
        name="OpenAI API Key",
        regex_pattern=r"\bsk-(?:proj-)?[a-zA-Z0-9_-]{48,120}\b",
        severity="CRITICAL",
        category="AI API Key",
        description="An OpenAI API Key was detected. Unauthorized users can use this key to make API calls, incurring costs.",
        remediation="Revoke the key immediately in the OpenAI API dashboard under API Keys. Check your billing dashboard for any unexpected usage spikes."
    ),
    Rule(
        rule_id="gemini-api-key",
        name="Gemini API Key",
        regex_pattern=r"\bAIzaSy[A-Za-z0-9_-]{33}\b",
        severity="CRITICAL",
        category="AI API Key",
        description="A Gemini / Google AI API Key was detected. Provides access to Google Generative AI APIs.",
        remediation="Go to Google AI Studio, locate the key, and revoke or rotate it. Set usage quotas to minimize potential financial loss."
    ),
    Rule(
        rule_id="anthropic-api-key",
        name="Anthropic API Key",
        regex_pattern=r"\bsk-ant-(?:sid01-)?[a-zA-Z0-9_-]{90,120}\b",
        severity="CRITICAL",
        category="AI API Key",
        description="An Anthropic (Claude) API Key was detected.",
        remediation="Deactivate the API key immediately in the Anthropic Console. Rotate the key and inject the new one using environment variables."
    ),
    Rule(
        rule_id="groq-api-key",
        name="Groq API Key",
        regex_pattern=r"\bgsk_[a-zA-Z0-9]{56}\b",
        severity="CRITICAL",
        category="AI API Key",
        description="A Groq Cloud API Key was detected.",
        remediation="Go to the Groq Console, delete the leaked API key, and create a new one. Ensure it is stored in a secure secret store or .env file."
    ),
    Rule(
        rule_id="openrouter-api-key",
        name="OpenRouter API Key",
        regex_pattern=r"\bsk-or-v1-[a-zA-Z0-9]{64}\b",
        severity="CRITICAL",
        category="AI API Key",
        description="An OpenRouter API Key was detected. This allows LLM access across multiple endpoints with shared billing.",
        remediation="Revoke the key immediately in the OpenRouter dashboard. Monitor keys and set limits to avoid unexpected token usage costs."
    ),

    # GitHub & GitLab
    Rule(
        rule_id="github-pat",
        name="GitHub Personal Access Token",
        regex_pattern=r"\b(?:ghp|gho|ghs|ghu|ghr)_[A-Za-z0-9_]{36}\b|\bgithub_pat_[A-Za-z0-9_]{82}\b",
        severity="HIGH",
        category="VCS Credentials",
        description="A GitHub Access Token (Classic or Fine-grained) was detected. Grants API access to GitHub repositories and user actions.",
        remediation="Go to GitHub settings > Developer settings > Personal access tokens. Revoke the token immediately. Identify what permissions it had and check audit logs for unauthorized actions."
    ),
    Rule(
        rule_id="gitlab-pat",
        name="GitLab Personal Access Token",
        regex_pattern=r"\bglpat-[A-Za-z0-9\-=_]{20,30}\b",
        severity="HIGH",
        category="VCS Credentials",
        description="A GitLab Personal Access Token was detected.",
        remediation="Revoke the token in GitLab under User Settings > Access Tokens. Generate a new token and update your credentials."
    ),

    # Database URIs
    Rule(
        rule_id="mongodb-uri",
        name="MongoDB Connection URI",
        regex_pattern=r"mongodb(?:\+srv)?:\/\/[A-Za-z0-9_.~-]+:[^@\s]+@[A-Za-z0-9_.-]+(?::\d+)?\/?[^\s\"']*",
        severity="CRITICAL",
        category="Database Connection",
        description="A MongoDB connection string containing a username and password in plaintext was detected.",
        remediation="Change the password of the database user immediately. Restrict database network access to specific trusted IPs (e.g. AWS Security Groups, MongoDB Atlas IP Access List). Put credentials in environment variables."
    ),
    Rule(
        rule_id="postgres-uri",
        name="PostgreSQL Connection URI",
        regex_pattern=r"postgres(?:ql)?:\/\/[A-Za-z0-9_.~-]+:[^@\s]+@[A-Za-z0-9_.-]+(?::\d+)?\/?[^\s\"']*",
        severity="CRITICAL",
        category="Database Connection",
        description="A PostgreSQL connection string containing a username and password in plaintext was detected.",
        remediation="Immediately rotate the password for this database user. Ensure the database port (default 5432) is not open to the public web. Enable SSL connections."
    ),
    Rule(
        rule_id="mysql-uri",
        name="MySQL Connection URI",
        regex_pattern=r"mysql:\/\/[A-Za-z0-9_.~-]+:[^@\s]+@[A-Za-z0-9_.-]+(?::\d+)?\/?[^\s\"']*",
        severity="CRITICAL",
        category="Database Connection",
        description="A MySQL connection string containing a username and password in plaintext was detected.",
        remediation="Rotate the user password in MySQL immediately. Prevent external connection from wildcards (e.g., '@%') and bind to localhost or private network IPs only."
    ),

    # Stripe & Twilio
    Rule(
        rule_id="stripe-api-key",
        name="Stripe API Key",
        regex_pattern=r"\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,100}\b",
        severity="CRITICAL",
        category="Payment Gateway",
        description="A Stripe API secret key or restricted key was detected. Compromise allows reading/writing financial and customer data.",
        remediation="Go to the Stripe Dashboard > Developers > API Keys. Roll the key immediately to revoke it and generate a replacement. Never expose live Stripe keys in frontends or source code."
    ),
    Rule(
        rule_id="twilio-auth-token",
        name="Twilio Auth Token / Account SID",
        regex_pattern=r"\bAC[a-fA-F0-9]{32}\b|\btwilio_auth_token(?:[\"']?\s*[:=]\s*[\"']?)([a-fA-F0-9]{32})",
        severity="HIGH",
        category="Communication API",
        description="A Twilio Account SID or Auth Token was detected. Allows sending SMS, placing calls, or accessing call logs.",
        remediation="Log in to the Twilio Console and rotate your Auth Token. Replace it in your system using environment variables. Monitor usage logs for fraudulent charges.",
        is_case_sensitive=False
    ),

    # Slack & Discord
    Rule(
        rule_id="slack-token",
        name="Slack OAuth/Bot Token",
        regex_pattern=r"\bxox[bapts]-[0-9]{10,12}-[A-Za-z0-9]{10,30}\b",
        severity="HIGH",
        category="Messaging API",
        description="A Slack bot, user, or workspace token was detected. Grants reading messages, uploading files, or sending webhooks.",
        remediation="Revoke the token in the Slack App Developer console. Regenerate the bot token and reinstall the app to your workspace."
    ),
    Rule(
        rule_id="slack-webhook",
        name="Slack Incoming Webhook",
        regex_pattern=r"https:\/\/hooks\.slack\.com\/services\/[T0-9A-Za-z]+\/[B0-9A-Za-z]+\/[0-9A-Za-z]+",
        severity="MEDIUM",
        category="Messaging API",
        description="A Slack incoming webhook URL was detected. Anyone can post formatted spam or phishing messages into your channels.",
        remediation="Delete the incoming webhook in your Slack App admin settings and create a new one. Do not hardcode webhook URLs in source code."
    ),
    Rule(
        rule_id="discord-bot-token",
        name="Discord Bot Token",
        regex_pattern=r"\b[MNORhQ][a-zA-Z0-9_\-\.]{23,25}\.[a-zA-Z0-9_\-\.]{6}\.[a-zA-Z0-9_\-\.]{27}\b",
        severity="CRITICAL",
        category="Messaging API",
        description="A Discord Bot Token was detected. Allows taking full control of the bot client, accessing messages, or managing guilds.",
        remediation="Go to the Discord Developer Portal, select your application, click Bot, and click 'Reset Token' to invalidate the old one."
    ),
    Rule(
        rule_id="discord-webhook",
        name="Discord Webhook URL",
        regex_pattern=r"https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9_\-]+",
        severity="MEDIUM",
        category="Messaging API",
        description="A Discord webhook URL was detected. Allows unauthorized posts to your channels.",
        remediation="Delete the webhook from channel integrations settings in your Discord server."
    ),

    # Hugging Face
    Rule(
        rule_id="huggingface-token",
        name="HuggingFace Token",
        regex_pattern=r"\bhf_[a-zA-Z0-9]{34,250}\b",
        severity="HIGH",
        category="AI API Key",
        description="A Hugging Face User Access Token was detected. Grants read/write access to repositories, models, datasets, and Spaces.",
        remediation="Revoke the token in Hugging Face settings under Access Tokens. Create a new token with minimal necessary permissions."
    ),

    # Generic & Common formats
    Rule(
        rule_id="jwt-token",
        name="JSON Web Token (JWT)",
        regex_pattern=r"\beyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_+/=]*",
        severity="MEDIUM",
        category="Token",
        description="A JSON Web Token (JWT) was detected. Depending on the payload, this could contain sensitive user identity or claims.",
        remediation="Ensure JWTs are not hardcoded. Rotate the signing key/secret on the authentication server if this token is a permanent session token or contains private API access."
    ),
    Rule(
        rule_id="bearer-token",
        name="Bearer Token",
        regex_pattern=r"(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*",
        severity="MEDIUM",
        category="Token",
        description="A Bearer token pattern was detected in the file. Bearer tokens carry authorization credentials.",
        remediation="Replace hardcoded authorization headers with environment variables or secure credential retrieval systems."
    ),
    Rule(
        rule_id="generic-password",
        name="Plaintext Password Assignment",
        regex_pattern=r"(?i)\b(?:password|passwd|pwd|secret_value)(?:[\"']?\s*[:=]\s*[\"'])([A-Za-z0-9_@#$!%*?&]{6,40})(?:[\"'])",
        severity="MEDIUM",
        category="Credential",
        description="A hardcoded password or credential assignment was detected.",
        remediation="Remove hardcoded passwords from code and configuration files. Store them in a secure environment file (.env) or use a secrets manager."
    ),
    Rule(
        rule_id="oauth-token",
        name="OAuth Client Secret / Token",
        regex_pattern=r"(?i)oauth_(?:client_)?(?:secret|token)(?:[\"']?\s*[:=]\s*[\"']?)([A-Za-z0-9\-._~]{20,50})",
        severity="HIGH",
        category="Credential",
        description="An OAuth Client Secret or token was detected. Grants server-side application authentication permissions.",
        remediation="Rotate client secrets in your OAuth provider console (Google, Facebook, GitHub, etc.) and update the environment config."
    )
]

def check_regex_match(text: str) -> List[Dict[str, Any]]:
    """Checks input text against all defined regex rules."""
    findings = []
    
    # We will search line by line to get line numbers and columns, or scan block
    lines = text.splitlines()
    for line_num, line_content in enumerate(lines, start=1):
        for rule in SECRET_RULES:
            for match in rule.regex.finditer(line_content):
                # Avoid matching empty strings
                secret = match.group(0)
                if not secret or len(secret.strip()) < 4:
                    continue
                
                # Check for sub-groups. If a rule specifies a capture group (like secret keys),
                # we only want to report the group value as the secret to avoid capturing the label.
                matched_secret = secret
                start_col = match.start() + 1
                end_col = match.end() + 1
                
                if match.groups():
                    # If there's a capture group, take the first capture group as the actual secret
                    captured = match.group(1)
                    if captured:
                        matched_secret = captured
                        # Adjust start/end col
                        idx = line_content.find(captured, match.start())
                        if idx != -1:
                            start_col = idx + 1
                            end_col = start_col + len(captured)
                
                findings.append({
                    "rule_id": rule.rule_id,
                    "rule_name": rule.name,
                    "severity": rule.severity,
                    "category": rule.category,
                    "secret": matched_secret,
                    "description": rule.description,
                    "remediation": rule.remediation,
                    "line_number": line_num,
                    "start_column": start_col,
                    "end_column": end_col,
                    "line_content": line_content.strip()
                })
                
    return findings
