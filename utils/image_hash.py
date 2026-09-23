"""
Detection of repeated scam images using perceptual hashing (pHash).

Screenshots used in this scam get reused as-is (or with minor edits: crop,
compression, watermark) across thousands of messages, so a perceptual hash
catches them even when they're not byte-for-byte identical.
"""
import io
import json
import logging
from pathlib import Path
from typing import List, Optional, Tuple

import aiohttp
import imagehash
from PIL import Image

log = logging.getLogger("anti_scam_bot.image_hash")


def _load_db(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        return {}
    return json.loads(p.read_text(encoding="utf-8"))


def _save_db(path: str, db: dict) -> None:
    Path(path).write_text(json.dumps(db, indent=2, ensure_ascii=False), encoding="utf-8")


async def download_bytes(url: str, max_bytes: Optional[int] = None) -> Optional[bytes]:
    """
    Download a URL's bytes.

    If max_bytes is set, the download aborts as soon as it's known to exceed
    that size (checked via the Content-Length header when present, and again
    while streaming in case the header is missing or wrong) instead of
    reading an unbounded amount of data into memory. This caps how much
    bandwidth/CPU a flood of oversized attachments can cost the bot.
    """
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status != 200:
                    return None

                if max_bytes is None:
                    return await resp.read()

                content_length = resp.headers.get("Content-Length")
                if content_length and int(content_length) > max_bytes:
                    log.info("Skipping %s: reported size exceeds the limit", url)
                    return None

                chunks = bytearray()
                async for chunk in resp.content.iter_chunked(65536):
                    chunks.extend(chunk)
                    if len(chunks) > max_bytes:
                        log.info("Skipping %s: exceeded size limit while downloading", url)
                        return None
                return bytes(chunks)
    except Exception as e:
        log.warning("Couldn't download %s: %s", url, e)
    return None


def compute_phash(image_bytes: bytes) -> Optional[str]:
    try:
        img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
        return str(imagehash.phash(img))
    except Exception as e:
        log.warning("Couldn't process the image: %s", e)
        return None


async def score_attachment_urls(
    urls: List[str],
    db_path: str = "data/known_hashes.json",
    hamming_threshold: int = 8,
    max_bytes: Optional[int] = None,
) -> Tuple[int, List[str], List[str], List[Tuple[str, bytes]]]:
    """
    Compare each image against the known-hashes database.

    Returns (score, details, matched_urls, unmatched_images). matched_urls contains only the
    URLs of images that actually matched a known scam hash -- this is used
    upstream to decide which image (if any) gets shown as evidence, so an
    unrelated attachment on the same message never ends up displayed in the
    mod-log alert. unmatched_images contains (url, bytes) for those that didn't match.
    """
    if not urls:
        return 0, [], [], []

    db = _load_db(db_path)
    if not db:
        pass # We still need to download and return them as unmatched

    total = 0
    details = []
    matched_urls = []
    unmatched_images = []

    for url in urls:
        raw = await download_bytes(url, max_bytes=max_bytes)
        if raw is None:
            continue
        h = compute_phash(raw)
        if h is None:
            unmatched_images.append((url, raw))
            continue

        this_hash = imagehash.hex_to_hash(h)
        best_label, best_distance = None, None
        
        if db:
            for known_hex, label in db.items():
                distance = this_hash - imagehash.hex_to_hash(known_hex)
                if best_distance is None or distance < best_distance:
                    best_distance, best_label = distance, label

        if best_distance is not None and best_distance <= hamming_threshold:
            total += 10
            details.append(f"image: matches '{best_label}' (distance {best_distance})")
            matched_urls.append(url)
        else:
            unmatched_images.append((url, raw))

    return total, details, matched_urls, unmatched_images


async def add_known_hash(url: str, label: str, db_path: str = "data/known_hashes.json") -> bool:
    """
    Add a confirmed scam image to the database (used by the !addhash command).
    No size cap here: this is an explicit, permission-gated moderator action,
    not automatic processing of arbitrary user content.
    """
    raw = await download_bytes(url)
    if raw is None:
        return False
    h = compute_phash(raw)
    if h is None:
        return False

    db = _load_db(db_path)
    db[h] = label
    _save_db(db_path, db)
    return True
