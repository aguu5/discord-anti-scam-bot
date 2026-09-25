import pytest
from unittest.mock import MagicMock, AsyncMock
from cogs.scam_detector import ScamDetector
from datetime import datetime, timezone, timedelta

class DummyBot:
    def __init__(self):
        self.config = {}

@pytest.fixture
def cog():
    cog_instance = ScamDetector(DummyBot())
    cog_instance.db = AsyncMock()
    return cog_instance

def test_is_exempt(cog):
    guild_cfg = {"exempt_role_ids": [123]}
    
    mock_member = MagicMock()
    mock_role = MagicMock()
    mock_role.id = 123
    mock_member.roles = [mock_role]
    
    assert cog._is_exempt(mock_member, guild_cfg) is True
    
    mock_role2 = MagicMock()
    mock_role2.id = 456
    mock_member.roles = [mock_role2]
    assert cog._is_exempt(mock_member, guild_cfg) is False

@pytest.mark.asyncio
async def test_register_burst(cog):
    guild_cfg = {"burst_window_seconds": 10, "burst_message_count": 3}
    guild_id = 111
    user_id = 999
    
    # Simulate DB returning count < limit
    cog.db.register_burst_and_count.return_value = 1
    assert await cog._register_burst(guild_id, user_id, has_link=True, guild_cfg=guild_cfg) == 0
    
    # Simulate DB returning count >= limit
    cog.db.register_burst_and_count.return_value = 4
    assert await cog._register_burst(guild_id, user_id, has_link=True, guild_cfg=guild_cfg) == 4

@pytest.mark.asyncio
async def test_register_burst_no_link(cog):
    guild_cfg = {"burst_window_seconds": 10, "burst_message_count": 3}
    guild_id = 111
    user_id = 888
    
    # When has_link is False, it returns 0 immediately without hitting DB
    assert await cog._register_burst(guild_id, user_id, has_link=False, guild_cfg=guild_cfg) == 0
    cog.db.register_burst_and_count.assert_not_called()

def test_is_new_account(cog):
    guild_cfg = {"new_account_days_threshold": 7}
    mock_member = MagicMock()
    
    mock_member.created_at = datetime.now(timezone.utc) - timedelta(days=2)
    assert cog._is_new_account(mock_member, guild_cfg) is True
    
    mock_member.created_at = datetime.now(timezone.utc) - timedelta(days=10)
    assert cog._is_new_account(mock_member, guild_cfg) is False

@pytest.mark.asyncio
async def test_independent_guild_dm_messages():
    from utils.db import ScamDb
    db = ScamDb(":memory:")
    await db.connect()
    
    # Init config for guild 1 (ensures row exists)
    await db.get_guild_config(1)
    await db.update_guild_config(1, "dm_message", "Message for Guild 1")
    # Init config for guild 2 (ensures row exists)
    await db.get_guild_config(2)
    await db.update_guild_config(2, "dm_message", "Message for Guild 2")
    
    config1 = await db.get_guild_config(1)
    config2 = await db.get_guild_config(2)
    
    assert config1["dm_message"] == "Message for Guild 1"
    assert config2["dm_message"] == "Message for Guild 2"
    
    await db.close()
