"""
Suspicious link checking.

This isn't meant to be a full scanner: it's a first line of defense based on
lists + simple heuristics. For something more robust you could add an
external API like Google Safe Browsing (see README, "future improvements").
"""
import re
import whois
import asyncio
from datetime import datetime
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

async def score_links(content: str, blocklist_path: str = "data/blocklist_domains.txt", db=None, suspicious_domain_age_days: int = 30) -> Tuple[int, List[str]]:
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

        # WHOIS check for domains not in the blocklist
        if db is not None:
            creation_date_ts = await db.get_whois_cache(domain)
            if creation_date_ts is None:
                try:
                    w = await asyncio.to_thread(whois.whois, domain)
                    if w.creation_date:
                        dt = w.creation_date
                        if isinstance(dt, list):
                            dt = dt[0]
                        if isinstance(dt, datetime):
                            creation_date_ts = dt.timestamp()
                except Exception:
                    pass
                await db.set_whois_cache(domain, creation_date_ts or 0.0)

            if creation_date_ts and creation_date_ts > 0:
                age_days = (datetime.now().timestamp() - creation_date_ts) / 86400.0
                if age_days < suspicious_domain_age_days:
                    total += 2
                    details.append(f"link: domain is recently registered ({age_days:.1f} days)")

    return total, details
