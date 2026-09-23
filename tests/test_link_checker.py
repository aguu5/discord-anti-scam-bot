import pytest
from utils.link_checker import score_links, extract_urls

def test_extract_urls():
    assert extract_urls("hello https://example.com world") == ["https://example.com"]
    assert extract_urls("no urls here") == []

def test_score_links_empty(tmp_path):
    blocklist = tmp_path / "blocklist.txt"
    blocklist.write_text("")
    score, details = score_links("", str(blocklist))
    assert score == 0
    assert details == []

def test_score_links_blocklist(tmp_path):
    blocklist = tmp_path / "blocklist.txt"
    blocklist.write_text("baddomain.com\nanotherbad.org")
    score, details = score_links("https://baddomain.com/test", str(blocklist))
    assert score == 6
    assert any("blocklist" in d for d in details)

def test_score_links_shortener(tmp_path):
    blocklist = tmp_path / "blocklist.txt"
    blocklist.write_text("")
    score, details = score_links("https://bit.ly/123", str(blocklist))
    assert score == 2
    assert any("shortener" in d for d in details)

def test_score_links_suspicious_keyword(tmp_path):
    blocklist = tmp_path / "blocklist.txt"
    blocklist.write_text("")
    score, details = score_links("https://free-nitro.example.com", str(blocklist))
    assert score == 3
    assert any("suspicious keyword" in d for d in details)
