import pytest
import asyncio
from unittest.mock import patch
import pytesseract
import utils.ocr
from utils.ocr import extract_text, get_tesseract_version

@pytest.fixture(autouse=True)
def reset_ocr_state():
    utils.ocr._tesseract_warning_logged = False
    yield

def test_get_tesseract_version_found():
    with patch("pytesseract.get_tesseract_version", return_value="5.3.0"):
        assert get_tesseract_version() == "5.3.0"

def test_get_tesseract_version_not_found():
    with patch("pytesseract.get_tesseract_version", side_effect=pytesseract.TesseractNotFoundError()):
        assert get_tesseract_version() is None

@pytest.mark.asyncio
async def test_extract_text_not_found(caplog):
    with patch("pytesseract.image_to_string", side_effect=pytesseract.TesseractNotFoundError()), \
         patch("utils.ocr.Image.open"):
        res1 = await extract_text(b"fake_image_data")
        assert res1 == ""
        
        res2 = await extract_text(b"fake_image_data")
        assert res2 == ""
        
        warnings = [record for record in caplog.records if record.levelname == "WARNING"]
        assert len(warnings) == 1
        assert "Tesseract not found" in warnings[0].message

@pytest.mark.asyncio
async def test_extract_text_other_exception(caplog):
    with patch("pytesseract.image_to_string", side_effect=Exception("Other error")), \
         patch("utils.ocr.Image.open"):
        res = await extract_text(b"fake_image_data")
        assert res == ""
        
        warnings = [record for record in caplog.records if record.levelname == "WARNING"]
        assert len(warnings) == 1
        assert "OCR failed: Other error" in warnings[0].message
