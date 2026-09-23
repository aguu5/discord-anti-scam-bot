import pytest
from unittest.mock import MagicMock
from cogs.scam_detector import ScamDetector

class DummyBot:
    def __init__(self):
        self.config = {}

@pytest.fixture
def cog():
    return ScamDetector(DummyBot())

def test_is_exempt(cog):
    cog.cfg = {"exempt_role_ids": [123]}
    
    mock_member = MagicMock()
    mock_role = MagicMock()
    mock_role.id = 123
    mock_member.roles = [mock_role]
    
    assert cog._is_exempt(mock_member) is True
    
    mock_role2 = MagicMock()
    mock_role2.id = 456
    mock_member.roles = [mock_role2]
    assert cog._is_exempt(mock_member) is False

def test_register_burst(cog):
    # Test bursting
    cog.cfg = {"burst_window_seconds": 10, "burst_limit": 3}
    user_id = 999
    assert cog._register_burst(user_id, has_link=True) == 0
    assert cog._register_burst(user_id, has_link=True) == 0
    assert cog._register_burst(user_id, has_link=True) == 4 # Hits limit

def test_register_burst_no_link(cog):
    cog.cfg = {"burst_window_seconds": 10, "burst_limit": 3}
    user_id = 888
    assert cog._register_burst(user_id, has_link=False) == 0
    assert cog._register_burst(user_id, has_link=False) == 0
    assert cog._register_burst(user_id, has_link=False) == 0

def test_is_new_account(cog):
    cog.cfg = {"new_account_days": 7}
    mock_member = MagicMock()
    
    from datetime import datetime, timezone, timedelta
    mock_member.created_at = datetime.now(timezone.utc) - timedelta(days=2)
    assert cog._is_new_account(mock_member) is True
    
    mock_member.created_at = datetime.now(timezone.utc) - timedelta(days=10)
    assert cog._is_new_account(mock_member) is False
