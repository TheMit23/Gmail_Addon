from typing import List
import re
from models import EmailData, Finding, Severity

def extract_email_address(text: str) -> str:
    if not text:
        return ""
    match = re.search(r'[\w\.-]+@[\w\.-]+', text)
    return match.group(0) if match else text.strip()

def analyze_security_headers(email: EmailData) -> List[Finding]:
    findings = []
    sender_clean = extract_email_address(email.sender.lower())
    
    # 1. Reply-To Mismatch
    if email.reply_to:
        reply_to_clean = extract_email_address(email.reply_to.lower())
        if sender_clean and reply_to_clean and sender_clean != reply_to_clean:
            findings.append(Finding(
                category="Authentication",
                description=f"Reply-To mismatch: Replies are diverted to '{reply_to_clean}'",
                severity=Severity.HIGH
            ))

    # 2. Return-Path Mismatch
    if email.return_path:
        return_path_clean = extract_email_address(email.return_path.lower())
        sender_domain = sender_clean.split('@')[-1] if '@' in sender_clean else ""
        return_path_domain = return_path_clean.split('@')[-1] if '@' in return_path_clean else ""
        
        if sender_domain and return_path_domain and sender_domain != return_path_domain:
            findings.append(Finding(
                category="Authentication",
                description="Return-Path mismatch: Source domain differs from network path",
                severity=Severity.MEDIUM
            ))

    # 3. SPF / DKIM / DMARC
    if email.auth_results:
        auth_lower = email.auth_results.lower()
        if "spf=fail" in auth_lower:
            findings.append(Finding(category="Authentication", description="SPF Failure", severity=Severity.HIGH))
        if "dkim=fail" in auth_lower:
            findings.append(Finding(category="Authentication", description="DKIM Failure", severity=Severity.HIGH))
        if "dmarc=fail" in auth_lower:
            findings.append(Finding(category="Authentication", description="DMARC Failure", severity=Severity.CRITICAL))

    return findings