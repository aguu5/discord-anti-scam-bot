import asyncio
import io
import logging
import pytesseract
from PIL import Image

log = logging.getLogger(__name__)
_tesseract_warning_logged = False

def get_tesseract_version() -> str | None:
    try:
        return str(pytesseract.get_tesseract_version())
    except pytesseract.TesseractNotFoundError:
        return None

async def extract_text(image_bytes: bytes) -> str:
    """
    Extracts text from image bytes using pytesseract.
    """
    def _extract():
        global _tesseract_warning_logged
        try:
            image = Image.open(io.BytesIO(image_bytes))
            return pytesseract.image_to_string(image)
        except pytesseract.TesseractNotFoundError:
            if not _tesseract_warning_logged:
                log.warning("Tesseract not found. OCR is disabled.")
                _tesseract_warning_logged = True
            return ""
        except Exception as e:
            log.warning("OCR failed: %s", e)
            return ""

    return await asyncio.to_thread(_extract)
