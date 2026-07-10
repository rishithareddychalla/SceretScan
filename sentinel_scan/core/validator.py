import requests
from typing import Dict, Any

def validate_openai_key(key: str) -> Dict[str, Any]:
    """Validates an OpenAI API key against the models endpoint."""
    url = "https://api.openai.com/v1/models"
    headers = {"Authorization": f"Bearer {key}"}
    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            return {"status": "active", "message": "Key is active. Retreived models list."}
        elif response.status_code == 401:
            return {"status": "inactive", "message": "Unauthorized: Invalid or revoked API key."}
        else:
            return {"status": "unverified", "message": f"Server responded with status {response.status_code}."}
    except Exception as e:
        return {"status": "unverified", "message": f"Network error: {str(e)}"}

def validate_github_token(token: str) -> Dict[str, Any]:
    """Validates a GitHub Personal Access Token against the user endpoint."""
    url = "https://api.github.com/user"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }
    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            scopes = response.headers.get("X-OAuth-Scopes", "none")
            return {"status": "active", "message": f"Token is active. Authenticated user. Scopes: {scopes}"}
        elif response.status_code == 401:
            return {"status": "inactive", "message": "Unauthorized: Token is invalid or has been revoked."}
        else:
            return {"status": "unverified", "message": f"GitHub returned status {response.status_code}."}
    except Exception as e:
        return {"status": "unverified", "message": f"Network error: {str(e)}"}

def validate_stripe_key(key: str) -> Dict[str, Any]:
    """Validates a Stripe API key against the charges endpoint."""
    url = "https://api.stripe.com/v1/charges"
    try:
        # Stripe uses Basic authentication with key as username
        response = requests.get(url, auth=(key, ""), timeout=5)
        if response.status_code == 200:
            return {"status": "active", "message": "Key is active. Authenticated Stripe charges endpoint."}
        elif response.status_code == 401:
            return {"status": "inactive", "message": "Unauthorized: Stripe key is invalid or expired."}
        else:
            return {"status": "unverified", "message": f"Stripe returned status {response.status_code}."}
    except Exception as e:
        return {"status": "unverified", "message": f"Network error: {str(e)}"}

def validate_gemini_key(key: str) -> Dict[str, Any]:
    """Validates a Gemini/Google AI key against the models endpoint."""
    url = f"https://generativelanguage.googleapis.com/v1beta/models?key={key}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            return {"status": "active", "message": "Key is active. Successfully fetched Google Gemini model metadata."}
        elif response.status_code == 400 or response.status_code == 403:
            return {"status": "inactive", "message": "Unauthorized/Forbidden: API Key is invalid or expired."}
        else:
            return {"status": "unverified", "message": f"Google AI returned status {response.status_code}."}
    except Exception as e:
        return {"status": "unverified", "message": f"Network error: {str(e)}"}

def validate_slack_webhook(url: str) -> Dict[str, Any]:
    """Validates a Slack Webhook by checking its endpoint structure."""
    if not url.startswith("https://hooks.slack.com/services/"):
        return {"status": "inactive", "message": "Invalid Slack webhook URL structure."}
    try:
        # Send post request with empty body or dummy text to check status
        response = requests.post(url, json={"text": "SentinelScan Security Verification Test"}, timeout=5)
        if response.status_code == 200:
            return {"status": "active", "message": "Webhook is live and active. Test post was accepted."}
        elif response.status_code in [403, 404]:
            return {"status": "inactive", "message": "Revoked: Webhook is invalid, expired, or removed."}
        else:
            return {"status": "unverified", "message": f"Slack API returned status {response.status_code}."}
    except Exception as e:
        return {"status": "unverified", "message": f"Network error: {str(e)}"}

def verify_secret_status(rule_id: str, secret: str) -> Dict[str, Any]:
    """Routes the validation task to the correct vendor API validator."""
    if not secret:
        return {"status": "unverified", "message": "No secret content provided."}
        
    normalized_rule = rule_id.lower()
    
    if "openai" in normalized_rule:
        return validate_openai_key(secret)
    elif "github" in normalized_rule:
        return validate_github_token(secret)
    elif "stripe" in normalized_rule:
        return validate_stripe_key(secret)
    elif "gemini" in normalized_rule:
        return validate_gemini_key(secret)
    elif "slack-webhook" in normalized_rule or "slack_webhook" in normalized_rule:
        return validate_slack_webhook(secret)
    else:
        return {
            "status": "unverified",
            "message": "This credential type does not support automated remote verification."
        }
