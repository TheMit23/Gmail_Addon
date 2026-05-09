from collections import defaultdict
from typing import Dict, List, Tuple

from models import Finding, Severity

# Severity base weights (before category multiplier and diminishing factor).
SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 45,
    Severity.HIGH: 25,
    Severity.MEDIUM: 10,
    Severity.LOW: 5,
    Severity.INFO: 0,
}

# Trust multipliers; keyword rows use explicit keys, other Content - * rows use LLM-style weight in _category_multiplier.
CATEGORY_MULTIPLIERS = {
    "Sender - Typosquatting": 1.3,
    "Authentication": 1.2,
    "Sender - Display Name": 1.1,
    "Attachments": 1.15,
    "Content - Subject": 0.8,
    "Content - Body": 0.7,
}

# Max points each pillar can contribute after summing (reduces runaway stacking).
PILLAR_CAPS: Dict[str, float] = {
    "authentication": 70.0,
    "sender": 60.0,
    "attachments": 80.0,
    "content": 75.0,
    "other": 30.0,
}

# Nth finding in the same pillar scales by DIMINISH[n] (strongest signals counted first).
DIMINISH = [1.0, 0.8, 0.6, 0.4]


def _pillar(category: str) -> str:
    if category == "Authentication":
        return "authentication"
    if category.startswith("Sender -"):
        return "sender"
    if category == "Attachments":
        return "attachments"
    if category.startswith("Content -"):
        return "content"
    return "other"


def _category_multiplier(category: str) -> float:
    if category in CATEGORY_MULTIPLIERS:
        return CATEGORY_MULTIPLIERS[category]
    if category.startswith("Content -"):
        return 0.9
    return 1.0


def calculate_risk_score(findings: List[Finding]) -> Tuple[int, str]:
    if not findings:
        return 0, "Safe"

    by_pillar: Dict[str, List[Finding]] = defaultdict(list)
    for f in findings:
        if f.severity == Severity.INFO:
            continue
        by_pillar[_pillar(f.category)].append(f)

    total_score = 0.0
    pillars_with_evidence: set[str] = set()

    for pillar, group in by_pillar.items():
        group_sorted = sorted(group, key=lambda x: x.severity.value, reverse=True)
        subtotal = 0.0
        for i, f in enumerate(group_sorted):
            base = SEVERITY_WEIGHTS.get(f.severity, 0)
            if base <= 0:
                continue
            mult = _category_multiplier(f.category)
            dim = DIMINISH[min(i, len(DIMINISH) - 1)]
            subtotal += base * mult * dim

        if subtotal > 0:
            pillars_with_evidence.add(pillar)

        cap = PILLAR_CAPS.get(pillar, 28.0)
        total_score += min(subtotal, cap)

    n_pillars = len(pillars_with_evidence)
    if n_pillars >= 3:
        total_score += 10.0
    elif n_pillars == 2:
        total_score += 4.0

    final_score = min(int(round(total_score)), 100)

    if final_score >= 75:
        verdict = "Malicious"
    elif final_score >= 40:
        verdict = "Suspicious"
    else:
        verdict = "Safe"

    return final_score, verdict
