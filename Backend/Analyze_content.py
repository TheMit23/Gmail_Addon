from typing import List
from models import EmailData, Finding, Severity

def analyze_content(email: EmailData) -> List[Finding]:
    findings = []
    subject = email.subject.lower()
    body = email.body.lower()
    
    # Subject Analysis
    critical_subject_patterns = ["suspended", "unauthorized", "action required", "urgent", "final notice"]
    if any(p in subject for p in critical_subject_patterns):
        findings.append(Finding(
            category="Content - Subject",
            description=f"Subject uses high-pressure language ('{subject}').",
            severity=Severity.HIGH
        ))

    financial_subject_patterns = ["invoice", "payment", "refund", "receipt", "transfer"]
    if any(p in subject for p in financial_subject_patterns):
        findings.append(Finding(
            category="Content - Subject",
            description="Subject mentions financial transactions, invoices or refunds.",
            severity=Severity.MEDIUM
        ))

    security_subject_patterns = ["security alert", "new login", "password reset", "verify your account"]
    if any(p in subject for p in security_subject_patterns):
        findings.append(Finding(
            category="Content - Subject",
            description="Subject claims to be a security alert or account verification.",
            severity=Severity.MEDIUM
        ))

    # Body Analysis
    # Call to Action (CTA) patterns
    if "click here" in body or "login to" in body or "verify now" in body:
        findings.append(Finding(
            category="Content - Body",
            description="The email body contains suspicious links or buttons (CTA).",
            severity=Severity.MEDIUM
        ))
        
    return findings