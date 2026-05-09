from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from Analyze_headers import analyze_security_headers
from Analyze_sender import analyze_sender
from Analyze_content import analyze_content
from Calculate_score import calculate_risk_score
from models import EmailData, AnalysisResult

app = FastAPI(title="Malicious Email Scorer")
@app.post("/analyze", response_model=AnalysisResult)
def analyze_email(email: EmailData):
    total_score = 0
    all_findings = []
       
    header_findings = analyze_security_headers(email)
    sender_findings = analyze_sender(email)
    content_findings = analyze_content(email)

    all_findings.extend(header_findings)
    all_findings.extend(sender_findings)
    all_findings.extend(content_findings)
    
    total_score, verdict = calculate_risk_score(all_findings) 
        
    return AnalysisResult(
        score=total_score,
        verdict=verdict,
        findings=all_findings
    )