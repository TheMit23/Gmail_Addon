import difflib
import unicodedata
from typing import List, Optional
from models import EmailData, Finding, Severity

TOP_DOMAINS = [
    "google.com", "gmail.com", "microsoft.com", "apple.com", "amazon.com", 
    "netflix.com", "facebook.com", "paypal.com", "outlook.com", "yahoo.com",
    "bankofamerica.com", "chase.com", "wellsfargo.com", "linkedin.com", "upwind.io"
]
FREE_PROVIDERS = [
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", 
    "icloud.com", "protonmail.com", "wallas.co.il"
]
def parse_sender_parts(sender_raw: str):
    name_part = ""
    email_part = sender_raw
    
    if "<" in sender_raw and ">" in sender_raw:
        name_part = sender_raw.split("<")[0].strip().replace('"', '')
        email_part = sender_raw.split("<")[1].split(">")[0].strip()
    
    return name_part, email_part.lower()
def check_domain_similarity(target_domain: str) -> Optional[str]:
    # NFKC normalization matters for homograph / confusable-domain detection.
    normalized_target = unicodedata.normalize('NFKC', target_domain).lower()
    
    for trusted_domain in TOP_DOMAINS:
        if normalized_target == trusted_domain:
            return None 
        
        similarity = difflib.SequenceMatcher(None, normalized_target, trusted_domain).ratio()
        if similarity >= 0.8:
            return trusted_domain
    return None

def analyze_sender(email: EmailData) -> List[Finding]:
    findings = []
    display_name, email_address = parse_sender_parts(email.sender)

    if "@" not in email_address:
        return findings

    domain = email_address.split('@')[-1]
    
    # Typosquatting
    similar_to = check_domain_similarity(domain)
    if similar_to:
        findings.append(Finding(
            category="Sender - Typosquatting",
            description=f"Domain '{domain}' is visually similar to trusted domain '{similar_to}'.",
            severity=Severity.CRITICAL 
        ))

    # Display Name Spoofing
    display_name_lower = display_name.lower()
    for trusted_domain in TOP_DOMAINS:
        brand_name = trusted_domain.split('.')[0]
        
        # Brand name appears in display name but domain is different - a common phishing tactic
        if brand_name in display_name_lower and brand_name not in domain:
            # The sender tries to impersonate a brand but uses a free email provider - high severity
            if any(prov in domain for prov in FREE_PROVIDERS):
                findings.append(Finding(
                    category="Sender - Display Name",
                    description=f"Sender claims to be '{brand_name}' but uses a free email provider ({domain}).",
                    severity=Severity.HIGH
                ))
            # Name looks legitimate but domain is unrelated - medium severity
            else:
                findings.append(Finding(
                    category="Sender - Display Name",
                    description=f"Display name mentions '{brand_name}' but the email domain is unrelated.",
                    severity=Severity.MEDIUM
                ))
            break

    return findings