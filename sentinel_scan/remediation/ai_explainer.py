import os
import json
import requests
from typing import Dict, Any, Optional

# Pre-defined, professional DevSecOps explanations for secret types
LOCAL_EXPLANATION_DATABASE = {
    "pem-private-key": {
        "risk_summary": "Exposing a private key allows attackers to impersonate the owner and gain full root/administrator access to servers or accounts associated with the public key.",
        "impact": "CRITICAL. Complete infrastructure compromise, unauthorized remote ssh logins, man-in-the-middle decryption of traffic, and data theft.",
        "action_steps": [
            "Immediately disable the corresponding public key in all authorized_keys files and cloud console endpoints.",
            "Generate a new secure keypair: 'ssh-keygen -t ed25519 -a 100'",
            "Deploy the new public key and store the new private key ONLY in a secure vault (e.g. HashiCorp Vault, AWS Secrets Manager) or as a masked environment secret in CI/CD."
        ]
    },
    "aws-secret-key": {
        "risk_summary": "An AWS Secret Access Key allows programmatic access to AWS services under the permissions of the compromised IAM user/role.",
        "impact": "CRITICAL. Attackers can spin up expensive GPU instances for crypto mining, delete databases/S3 buckets, exfiltrate user data, or ransom your organization.",
        "action_steps": [
            "Log into the AWS Console immediately, navigate to IAM, locate the compromised Access Key ID, and set it to 'Inactive'.",
            "Review AWS CloudTrail logs for any API calls made with this key in the last 24 hours.",
            "Delete the key from AWS IAM, generate a new one, and inject it as a runtime variable. Never put AWS keys in config files."
        ]
    },
    "aws-access-key": {
        "risk_summary": "An AWS Access Key ID identifies your AWS IAM account. While not a secret on its own, its exposure allows attackers to pair it with a secret key or target it for scanning.",
        "impact": "HIGH. Increases the attack surface. If an attacker discovers the paired secret key, your AWS resources are compromised.",
        "action_steps": [
            "Check if this key is active and rotate it in the AWS Console.",
            "Remove the key from source code and replace it with IAM Instance Profiles, ECS Task Roles, or AWS OIDC for GitHub Actions."
        ]
    },
    "gcp-service-account": {
        "risk_summary": "A GCP Service Account JSON key contains private keys that allow any application to assume the service account's identity and permissions.",
        "impact": "CRITICAL. Access to Google Cloud SQL, BigQuery datasets, GCS storage buckets, and App Engine/GKE clusters.",
        "action_steps": [
            "Go to GCP Console > IAM & Admin > Service Accounts.",
            "Select the compromised account, go to 'Keys' tab, and delete the leaked key ID immediately.",
            "Generate a new JSON key, configure it locally, and deploy it securely using Google Secrets Manager or Google Workload Identity Federation."
        ]
    },
    "openai-api-key": {
        "risk_summary": "An OpenAI API Key allows unauthorized access to models (like GPT-4o). Attackers scrape public repos for these keys to use them for their own applications, leaving you with massive bills.",
        "impact": "CRITICAL. Financial liability. Attackers can exhaust rate limits, access fine-tuned models containing company data, and incur massive usage charges.",
        "action_steps": [
            "Go to the OpenAI Platform dashboard > API Keys.",
            "Revoke the compromised key immediately by clicking the delete icon.",
            "Check your Usage history in the billing dashboard for unauthorized requests.",
            "Use environment variables (OPENAI_API_KEY) and configure usage limits on your billing account."
        ]
    },
    "gemini-api-key": {
        "risk_summary": "A Gemini API Key enables access to Google Generative AI services. If exposed, attackers can hijack the key for their own AI projects, leading to billing overruns.",
        "impact": "CRITICAL. Financial liability and rate limit exhaustion.",
        "action_steps": [
            "Open Google AI Studio, locate the leaked API key, and revoke it.",
            "Review your usage dashboards in Google Cloud Console. Set up billing alerts to catch anomalies early."
        ]
    },
    "postgres-uri": {
        "risk_summary": "A PostgreSQL connection URI exposes database server addresses, usernames, and plaintext passwords.",
        "impact": "CRITICAL. Full database compromise. Attackers can read, modify, or delete database tables, execute arbitrary code via extensions, or download customer data.",
        "action_steps": [
            "Connect to the PostgreSQL database using an admin account and rotate the password for the leaked user.",
            "Ensure the PostgreSQL instance (default port 5432) is not accessible from the public internet. Use a VPC, SSH tunnels, or AWS security groups.",
            "Enable SSL-only connections to prevent interception."
        ]
    },
    "mongodb-uri": {
        "risk_summary": "A MongoDB connection string exposes host IP addresses and authentication credentials.",
        "impact": "CRITICAL. Data exfiltration and database ransomware. Wiping MongoDB databases and replacing them with a ransom note is a highly automated attack.",
        "action_steps": [
            "Rotate the user password immediately via MongoDB Atlas or your local mongo shell.",
            "Configure IP Access Lists to restrict connections only to your application server IPs.",
            "Ensure database logs are reviewed for unauthorized connection attempts."
        ]
    },
    "github-pat": {
        "risk_summary": "A GitHub Personal Access Token (PAT) grants access to repositories, organizations, and user accounts depending on the token's scope.",
        "impact": "HIGH/CRITICAL. Attackers can read private source code, push malicious commits (supply chain attacks), modify release binaries, or steal organization secrets.",
        "action_steps": [
            "Go to GitHub Settings > Developer settings > Personal access tokens. Click 'Revoke' next to the compromised token.",
            "Inspect git commit logs and repository settings for unauthorized webhooks, collaborators, or deploy keys.",
            "Switch to Fine-Grained PATs with the absolute minimum scopes and short expiration dates."
        ]
    }
}

def get_ai_explanation(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Provides an explanation of the finding.
    If GEMINI_API_KEY or OPENAI_API_KEY is available in the environment,
    calls the respective generative model to get a custom, contextual explanation.
    Otherwise, falls back to the rich local rule-based database.
    """
    rule_id = finding.get("rule_id", "")
    secret_type = finding.get("rule_name", "Secret Key")
    severity = finding.get("severity", "MEDIUM")
    
    # 1. Attempt LLM AI Explanations
    gemini_key = os.environ.get("GEMINI_API_KEY")
    openai_key = os.environ.get("OPENAI_API_KEY")
    
    if gemini_key:
        try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={gemini_key}"
            prompt = f"""
            You are a senior DevSecOps engineer. Provide a concise, professional security explanation for a detected leak of:
            - Secret Type: {secret_type}
            - Severity: {severity}
            - Context Line: {finding.get('line_content', '')}
            
            Give the risk, potential impact, and clear action steps to fix it. Keep it to 3 short paragraphs max.
            """
            payload = {
                "contents": [{"parts": [{"text": prompt}]}]
            }
            res = requests.post(url, json=payload, timeout=5)
            if res.status_code == 200:
                data = res.json()
                text = data["candidates"][0]["content"]["parts"][0]["text"]
                return {
                    "provider": "Gemini AI",
                    "explanation": text.strip()
                }
        except Exception:
            pass  # Fallback to local
            
    if openai_key:
        try:
            url = "https://api.openai.com/v1/chat/completions"
            headers = {
                "Authorization": f"Bearer {openai_key}",
                "Content-Type": "application/json"
            }
            prompt = f"Provide a brief security risk explanation and remediation steps for a leaked {secret_type} ({severity} severity) in code."
            payload = {
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 300
            }
            res = requests.post(url, json=payload, headers=headers, timeout=5)
            if res.status_code == 200:
                data = res.json()
                text = data["choices"][0]["message"]["content"]
                return {
                    "provider": "OpenAI Chat",
                    "explanation": text.strip()
                }
        except Exception:
            pass  # Fallback to local
            
    # 2. Local Fallback Database
    entry = LOCAL_EXPLANATION_DATABASE.get(rule_id)
    if entry:
        explanation_text = f"**Risk Summary:** {entry['risk_summary']}\n\n"
        explanation_text += f"**Impact:** {entry['impact']}\n\n"
        explanation_text += "**Remediation Action Steps:**\n"
        for i, step in enumerate(entry["action_steps"], start=1):
            explanation_text += f"{i}. {step}\n"
            
        return {
            "provider": "SentinelScan Local Risk Engine",
            "explanation": explanation_text
        }
        
    # Default fallback
    default_text = (
        f"**Risk Summary:** A potential secret of type '{secret_type}' was found in plaintext in the codebase.\n\n"
        f"**Impact:** {severity}. If compromised, an attacker can use this key to access unauthorized resources, "
        "impersonate services, or cause financial loss.\n\n"
        "**Remediation Action Steps:**\n"
        "1. Immediately rotate and revoke this credential with the service provider.\n"
        "2. Do not commit secrets in plaintext. Use an environment variable file (.env) and list it in your .gitignore.\n"
        "3. Review system logs for unauthorized connections using this key."
    )
    return {
        "provider": "SentinelScan Standard Explainer",
        "explanation": default_text
    }
