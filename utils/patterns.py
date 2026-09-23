"""
Text patterns associated with this type of scam (celebrity + crypto/casino + urgency).
Each category adds points if it appears in a message. Real scam messages usually
combine several categories at once, so the score accumulates.

Note: the patterns themselves are kept bilingual (English + Spanish) on purpose,
since this scam campaign circulates in both languages on Discord. Everything
else (names, comments, output) is in English.
"""
import re
from typing import List, Tuple

# (category name, list of case-insensitive regex patterns, points per match)
PATTERN_CATEGORIES = [
    (
        "celebrity_mentioned",
        [r"\bmr ?beast\b", r"\belon ?musk\b", r"\bkai ?cenat\b"],
        2,
    ),
    (
        "crypto_casino_offer",
        [
            r"crypto ?casino", r"cripto ?casino", r"casino cripto",
            r"crypto ?bonus", r"bono (de )?(registro|bienvenida)",
            r"sign[- ]?up bonus", r"free bonus", r"bono gratis",
        ],
        3,
    ),
    (
        "promo_code",
        [r"promo ?code", r"c[oó]digo promocional", r"c[oó]digo de activaci[oó]n", r"activation code"],
        2,
    ),
    (
        "fake_urgency",
        [
            r"\bsolo hoy\b", r"\btiempo limitado\b", r"limited time",
            r"se elimina en \d+", r"expires? in \d+", r"antes de que se borre",
        ],
        2,
    ),
    (
        "large_amount",
        [r"\$\s?\d{1,3}(?:[.,]\d{3})+(?:\s?(usd|dolares|d[oó]lares))?\b"],
        1,
    ),
    (
        "you_won_phrase",
        [r"\bganaste\b", r"\byou('| ha)?ve won\b", r"\bcongratulations\b", r"\bfelicidades\b.*(ganad|selecc)"],
        2,
    ),
]

_COMPILED = [
    (name, [re.compile(p, re.IGNORECASE) for p in patterns], points)
    for name, patterns, points in PATTERN_CATEGORIES
]


def score_text(content: str) -> Tuple[int, List[str]]:
    """Return (total_score, matched_categories) for a given text."""
    if not content:
        return 0, []

    total = 0
    matched = []
    for name, compiled, points in _COMPILED:
        if any(p.search(content) for p in compiled):
            total += points
            matched.append(f"text: {name}")
    return total, matched
