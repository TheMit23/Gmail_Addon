import enum
from typing import List, Tuple
from models import Finding, Severity

def calculate_risk_score(findings: List[Finding]) -> Tuple[int, str]:
    if not findings:
        return 0, "Safe"

    # 1. הגדרת משקלים בסיסיים לכל רמת חומרה
    severity_weights = {
        Severity.CRITICAL: 45, # רמה 4 - כמעט חצי מהציון
        Severity.HIGH: 25,     # רמה 3
        Severity.MEDIUM: 10,   # רמה 2
        Severity.LOW: 5,       # רמה 1
        Severity.INFO: 0
    }

    # 2. מכפילים לפי קטגוריה (כמה אנחנו סומכים על המנוע הזה)
    category_multipliers = {
        "Sender - Typosquatting": 1.3, # הוכחה טכנית חזקה
        "Authentication": 1.2,         # הוכחה קריפטוגרפית
        "Sender - Display Name": 1.1,
        "Content - Subject": 0.8,      # יכול להיות False Positive
        "Content - Body": 0.7
    }

    total_score = 0
    categories_found = set()

    for f in findings:
        base_weight = severity_weights.get(f.severity, 0)
        multiplier = category_multipliers.get(f.category, 1.0)
        
        total_score += (base_weight * multiplier)
        categories_found.add(f.category)

    # 3. בונוס על שילוב קטגוריות (Pattern Detection)
    # אם יש גם בעיית שולח וגם בעיית תוכן, זה כנראה פישינג
    if len(categories_found) >= 3:
        total_score += 15
    elif len(categories_found) == 2:
        total_score += 5

    # 4. חסימה (Capping)
    final_score = min(int(total_score), 100)

    # 5. קביעת Verdict (פסק דין)
    if final_score >= 75:
        verdict = "Malicious"
    elif final_score >= 40:
        verdict = "Suspicious"
    else:
        verdict = "Safe"

    return final_score, verdict