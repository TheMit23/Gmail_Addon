from __future__ import annotations

import os
import re
from typing import List

from models import AttachmentMeta, EmailData, Finding, Severity

DANGEROUS_EXT = (
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".js", ".jse", ".vbs", ".wsf",
    ".ps1", ".msi", ".dll", ".jar", ".app", ".deb", ".rpm",
)
ARCHIVE_EXT = (".zip", ".rar", ".7z", ".gz", ".tar")

HIGH_RISK_MIME_PREFIXES = (
    "application/x-msdownload",
    "application/x-dosexec",
    "application/x-msdos-program",
    "application/x-executable",
)

DOUBLE_EXT_PATTERN = re.compile(
    r"\.[a-z0-9]{1,8}\.(exe|scr|bat|cmd|com|pif|zip|js|jar|msi)$",
    re.IGNORECASE,
)


def _ext(name: str) -> str:
    return os.path.splitext(name.lower())[1]


def analyze_attachments(email: EmailData) -> List[Finding]:
    atts: List[AttachmentMeta] = list(email.attachments or [])
    if not atts:
        return []

    findings: List[Finding] = []
    dangerous_ext_count = 0
    archive_count = 0
    double_ext_hits = 0
    octet_stream_exec_like = 0
    high_risk_mime = 0
    total_bytes = 0

    for a in atts:
        name = (a.filename or "attachment").strip()
        ext = _ext(name)
        mime = (a.mime_type or "").lower()
        total_bytes += max(a.size_bytes, 0)

        if ext in DANGEROUS_EXT:
            dangerous_ext_count += 1
        if ext in ARCHIVE_EXT:
            archive_count += 1
        if DOUBLE_EXT_PATTERN.search(name):
            double_ext_hits += 1
        if mime == "application/octet-stream" and ext in DANGEROUS_EXT + ARCHIVE_EXT:
            octet_stream_exec_like += 1
        if any(mime.startswith(p) for p in HIGH_RISK_MIME_PREFIXES):
            high_risk_mime += 1

    n = len(atts)
    findings.append(
        Finding(
            category="Attachments",
            description=f"Message has {n} attachment(s) (metadata-only scan; files were not opened).",
            severity=Severity.INFO,
        )
    )

    if double_ext_hits > 0:
        findings.append(
            Finding(
                category="Attachments",
                description=f"{double_ext_hits} attachment name(s) show a double extension (e.g. file.pdf.exe) — common malware trick.",
                severity=Severity.HIGH,
            )
        )
    if dangerous_ext_count > 0:
        findings.append(
            Finding(
                category="Attachments",
                description=f"{dangerous_ext_count} attachment(s) use executable/script extensions.",
                severity=Severity.HIGH,
            )
        )
    if high_risk_mime > 0:
        findings.append(
            Finding(
                category="Attachments",
                description=f"{high_risk_mime} attachment(s) advertise executable/binary MIME types.",
                severity=Severity.HIGH,
            )
        )
    if octet_stream_exec_like > 0:
        findings.append(
            Finding(
                category="Attachments",
                description=f"{octet_stream_exec_like} attachment(s) are generic binary/octet-stream with risky extensions.",
                severity=Severity.MEDIUM,
            )
        )
    if archive_count > 0:
        findings.append(
            Finding(
                category="Attachments",
                description=f"{archive_count} archive attachment(s) — malware often ships inside archives; verify sender before opening.",
                severity=Severity.MEDIUM,
            )
        )
    if n >= 5:
        findings.append(
            Finding(
                category="Attachments",
                description="Unusually high attachment count — inspect each file before opening.",
                severity=Severity.MEDIUM,
            )
        )
    if total_bytes >= 25 * 1024 * 1024:
        findings.append(
            Finding(
                category="Attachments",
                description="Very large total attachment size — unexpected for typical phishing but worth verifying.",
                severity=Severity.LOW,
            )
        )

    return findings
