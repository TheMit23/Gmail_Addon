from fastapi import FastAPI
from Analyze_headers import analyze_security_headers
from Analyze_sender import analyze_sender
from Analyze_attachments import analyze_attachments
from Analyze_content_ai import analyze_content_with_ai
from Calculate_score import calculate_risk_score
from models import EmailData, AnalysisResult, Severity
import asyncio

app = FastAPI(title="Malicious Email Scorer")
@app.post("/analyze", response_model=AnalysisResult)
async def analyze_email(email: EmailData):
    total_score = 0
    all_findings = []
    ai_task = asyncio.create_task(analyze_content_with_ai(email))
    header_findings = analyze_security_headers(email)
    sender_findings = analyze_sender(email)
    attachment_findings = analyze_attachments(email)

    content_findings = await ai_task
    all_findings.extend(header_findings)
    all_findings.extend(sender_findings)
    all_findings.extend(attachment_findings)
    all_findings.extend(content_findings)
    
    total_score, verdict = calculate_risk_score(all_findings)

    visible = [f for f in all_findings if f.severity != Severity.INFO]
    return AnalysisResult(
        score=total_score,
        verdict=verdict,
        findings=visible,
    )