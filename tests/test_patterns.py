import pytest
from utils.patterns import score_text

def test_score_text_empty():
    score, matches = score_text("")
    assert score == 0
    assert matches == []

def test_score_text_no_match():
    score, matches = score_text("hello world")
    assert score == 0
    assert matches == []

def test_score_text_single_match():
    score, matches = score_text("mr beast")
    assert score == 2
    assert "text: celebrity_mentioned" in matches

def test_score_text_multiple_matches():
    score, matches = score_text("mr beast crypto casino promo code")
    assert score == 2 + 3 + 2
    assert "text: celebrity_mentioned" in matches
    assert "text: crypto_casino_offer" in matches
    assert "text: promo_code" in matches

def test_score_text_case_insensitive():
    score, matches = score_text("MR bEaSt")
    assert score == 2
    assert "text: celebrity_mentioned" in matches
