import re
from google import genai
from typing import Any, List
from models import EmailData, Finding, Severity
import os
import json
from dotenv import load_dotenv

load_dotenv()
GEMINI_TOKEN = os.getenv("GEMINI_API_KEY")
client = genai.Client(api_key=GEMINI_TOKEN)


_URL_SNIPPET = re.compile(r"https?://\S+")


def _anonymize_segment(text: str) -> str:
    """Apply PII regexes to a slice that is not inside a URL (avoids mangling tracking IDs)."""
    text = re.sub(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "[EMAIL]", text)
    text = re.sub(
        r"\+?\d{1,4}?[-.\s]?\(?\d{1,3}?\)?[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,9}",
        "[PHONE]",
        text,
    )
    text = re.sub(r"\b\d{4}[-.\s]?\d{4}[-.\s]?\d{4}[-.\s]?\d{4}\b", "[CARD]", text)
    text = re.sub(r"\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b", "[SSN]", text)
    text = re.sub(r"\b\d{5}[-.\s]?\d{4}\b", "[ZIP]", text)
    return text


def anonymize_text(text: str) -> str:
    if not text:
        return text
    out: List[str] = []
    pos = 0
    for m in _URL_SNIPPET.finditer(text):
        out.append(_anonymize_segment(text[pos : m.start()]))
        out.append(m.group(0))
        pos = m.end()
    out.append(_anonymize_segment(text[pos:]))
    return "".join(out)


def _is_empty_mail(email: EmailData) -> bool:
    body = (email.body or "").strip()
    if body:
        return False
    sub = (email.subject or "").strip().lower()
    return sub == "" or sub in ("no subject", "(no subject)")


async def analyze_content_with_ai(email: EmailData) -> List[Finding]:
    findings = []

    if _is_empty_mail(email):
        return findings

    # Removing Personally Identifiable Information (PII) before sending to AI
    safe_subject = anonymize_text(email.subject)
    safe_body = anonymize_text(email.body)
    
    system_instruction = f"""
    You are an expert Cybersecurity Analyst specializing in Phishing and Social Engineering.
    Analyze the following email for psychological manipulation tactics.
    
    
    Look for these specific tactics:
    1. Sense of Urgency/Fear (Pressure to act fast)
    2. Authority Impersonation (Claiming to be CEO, Admin, Government)
    3. Emotion Manipulation (Greed, Curiosity, Panic)
    4. Suspicious Call to Action (Vague links or instructions)

    For each tactic found, provide:
    - Tactic Name
    - Brief Explanation (1 sentence)
    - Severity (Low, Medium, High, Critical)
    
    Return ONLY a JSON list of objects with these keys: 
    "category", "description", "severity" (1-4).
    If the email is safe, return an empty list [].
    """

    try:

        chat = client.aio.chats.create(
            model='gemini-2.5-flash',
            config={
                'system_instruction': system_instruction,
                'response_mime_type': 'application/json'
            }
        )
        prompt = f"Subject: {safe_subject}\n\nBody:\n{safe_body}"
        response = await chat.send_message(prompt)
        
        ai_findings = json.loads(response.text)

        for item in ai_findings:
            tactic = str(item.get("category", "Analysis")).strip() or "Analysis"
            findings.append(
                Finding(
                    category="Content - " + tactic,
                    description=item.get("description", ""),
                    severity=Severity(item.get("severity", 1)),
                )
            )
            
    except Exception as e:
        print(f"AI Error: {e}")
        
    return findings