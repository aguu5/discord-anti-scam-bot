import pytest
from unittest.mock import patch
from utils.image_hash import score_attachment_urls, add_known_hash
import imagehash
from PIL import Image
import io

def get_dummy_image_bytes():
    img = Image.new("RGB", (10, 10), color="red")
    buf = io.BytesIO()
    img.save(buf, format="JPEG")
    return buf.getvalue()

@pytest.fixture
def mock_download_bytes():
    with patch("utils.image_hash.download_bytes") as m:
        yield m

@pytest.mark.asyncio
async def test_score_attachment_urls_no_match(mock_download_bytes, tmp_path):
    mock_download_bytes.return_value = get_dummy_image_bytes()
    db_path = tmp_path / "known_hashes.json"
    db_path.write_text('{"ffffff0000000000": "fake_scam"}')
    
    score, details, matched, unmatched = await score_attachment_urls(
        ["https://example.com/img.jpg"],
        db_path=str(db_path)
    )
    assert score == 0
    assert details == []
    assert matched == []

@pytest.mark.asyncio
async def test_score_attachment_urls_match(mock_download_bytes, tmp_path):
    img_bytes = get_dummy_image_bytes()
    mock_download_bytes.return_value = img_bytes
    
    img = Image.open(io.BytesIO(img_bytes)).convert("RGB")
    real_hash = str(imagehash.phash(img))
    
    db_path = tmp_path / "known_hashes.json"
    import json
    db_path.write_text(json.dumps({real_hash: "test_scam"}))
    
    score, details, matched, unmatched = await score_attachment_urls(
        ["https://example.com/img.jpg"],
        db_path=str(db_path)
    )
    assert score == 10
    assert any("matches" in d for d in details)
    assert matched == ["https://example.com/img.jpg"]

@pytest.mark.asyncio
async def test_add_known_hash(mock_download_bytes, tmp_path):
    img_bytes = get_dummy_image_bytes()
    mock_download_bytes.return_value = img_bytes
    
    db_path = tmp_path / "known_hashes.json"
    db_path.write_text("{}")
    
    success = await add_known_hash("https://example.com/img.jpg", "new_label", db_path=str(db_path))
    assert success is True
    
    import json
    data = json.loads(db_path.read_text())
    assert len(data) == 1
    assert list(data.values())[0] == "new_label"
