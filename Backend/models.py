from enum import Enum
from pydantic import BaseModel, Field
from typing import List, Optional


class Severity(int, Enum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

class Finding(BaseModel):
    category: str
    description: str
    severity: Severity


class AttachmentMeta(BaseModel):
    filename: str = ""
    mime_type: str = ""
    size_bytes: int = Field(default=0, ge=0)


class EmailData(BaseModel):
    sender: str
    subject: str
    body: str
    reply_to: Optional[str] = None
    auth_results: Optional[str] = None
    return_path: Optional[str] = None
    body_html: Optional[str] = None
    attachments: Optional[List[AttachmentMeta]] = None

class AnalysisResult(BaseModel):
    score: int
    verdict: str
    findings: List[Finding]