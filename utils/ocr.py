import asyncio
import io
import pytesseract
from PIL import Image

async def extract_text(image_bytes: bytes) -> str:
    """
    Extracts text from image bytes using pytesseract.
    """
    def _extract():
        try:
            image = Image.open(io.BytesIO(image_bytes))
            return pytesseract.image_to_string(image)
        except Exception:
            return ""

    return await asyncio.to_thread(_extract)
