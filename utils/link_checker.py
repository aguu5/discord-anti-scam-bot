"""
Suspicious link checking.

This isn't meant to be a full scanner: it's a first line of defense based on
lists + simple heuristics. For something more robust you could add an
external API like Google Safe Browsing (see README, "future improvements").
"""
import re
from pathlib import Path
from typing import List, Set, Tuple
from urllib.parse import urlparse

URL_RE = re.compile(r"https?://[^\s<>\"]+", re.IGNORECASE)

KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly",
    "rebrand.ly", "shorturl.at", "rb.gy",
}

SUSPICIOUS_KEYWORDS_IN_DOMAIN = [
    "casino", "bet", "claim", "airdrop", "giveaway", "bonus",
    "crypto-", "-crypto", "wallet-connect", "free-nitro", "discord-nitro",
]


def _load_blocklist(path: str) -> Set[str]:
    p = Path(path)
    if not p.exists():
        return set()
    domains = set()
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip().lower()
        if line and not line.startswith("#"):
            domains.add(line)
    return domains


def extract_urls(content: str) -> List[str]:
    return URL_RE.findall(content or "")


def score_links(content: str, blocklist_path: str = "data/blocklist_domains.txt") -> Tuple[int, List[str]]:
    """Return (score, details) after analyzing every link in a message."""
    urls = extract_urls(content)
    if not urls:
        return 0, []

    blocklist = _load_blocklist(blocklist_path)
    total = 0
    details = []

    for url in urls:
        try:
            domain = urlparse(url).netloc.lower()
        except ValueError:
            continue
        if not domain:
            continue

        if domain in blocklist:
            total += 6
            details.append(f"link: domain in blocklist ({domain})")
            continue  # already strong enough evidence, no need to add more for this link

        if domain in KNOWN_SHORTENERS:
            total += 2
            details.append(f"link: URL shortener ({domain})")

        if any(kw in domain for kw in SUSPICIOUS_KEYWORDS_IN_DOMAIN):
            total += 3
            details.append(f"link: suspicious keyword in domain ({domain})")

    return total, details
