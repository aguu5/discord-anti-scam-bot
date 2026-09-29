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

@pytest.mark.asyncio
async def test_unset_dm_message_fallback(cog):
    from utils.db import ScamDb
    db = ScamDb(":memory:")
    await db.connect()
    
    guild_id = 9999
    guild_cfg = await db.get_guild_config(guild_id)
    assert guild_cfg["dm_message"] is None
    
    mock_message = MagicMock()
    mock_message.author.send = AsyncMock()
    mock_message.delete = AsyncMock()
    mock_message.author.timeout = AsyncMock()
    
    cog._send_alert = AsyncMock()
    
    await cog._act_on_message(mock_message, 10, ["test"], None, guild_cfg)
    
    await db.close()

@pytest.mark.asyncio
async def test_scan_channel_user_author(cog):
    import discord
    
    interaction = MagicMock()
    interaction.response.defer = AsyncMock()
    interaction.followup.send = AsyncMock()
    interaction.guild_id = 111
    
    mock_user = MagicMock(spec=discord.User)
    mock_user.bot = False
    mock_user.id = 12345
    
    mock_msg = MagicMock(spec=discord.Message)
    mock_msg.author = mock_user
    mock_msg.guild = MagicMock()
    mock_msg.content = "Mr Beast crypto casino promo code solo hoy $1,000 you've won http://scam.com"
    mock_msg.attachments = []
    
    # Setup history to yield mock_msg
    async def async_gen():
        yield mock_msg
    interaction.channel.history = MagicMock(return_value=async_gen())
    
    guild_cfg = {
        "alert_threshold": 3,
        "action_threshold": 6,
        "exempt_role_ids": [777]
    }
    cog.db.get_guild_config.return_value = guild_cfg
    
    mock_member = MagicMock(spec=discord.Member)
    mock_role = MagicMock()
    mock_role.id = 777
    mock_member.roles = [mock_role]
    
    # mock guild.get_member and guild.fetch_member on msg.guild
    mock_msg.guild.get_member = MagicMock(return_value=None)
    mock_msg.guild.fetch_member = AsyncMock(return_value=mock_member)
    
    cog.db.get_whois_cache.return_value = 0.0
    cog.db.increment_stat = AsyncMock()
    
    cog._act_on_message = AsyncMock()
    
    await cog.scan_channel.callback(cog, interaction, limit=1)
    
    # Because they are a member with an exempt role (after resolution), they should not be acted on
    cog._act_on_message.assert_not_called()

@pytest.mark.asyncio
async def test_resolve_member_cache(cog):
    import discord
    guild = MagicMock()
    guild.get_member.return_value = None
    guild.fetch_member = AsyncMock(return_value=MagicMock(spec=discord.Member))
    
    author = MagicMock(spec=discord.User)
    author.id = 999
    
    cache = {}
    
    res1 = await cog._resolve_member(guild, author, cache)
    assert res1 is not None
    assert cache[author.id] == res1
    assert guild.fetch_member.call_count == 1
    
    # second call should hit cache
    res2 = await cog._resolve_member(guild, author, cache)
    assert res2 is res1
    assert guild.fetch_member.call_count == 1

@pytest.mark.asyncio
async def test_resolve_member_not_found(cog):
    import discord
    guild = MagicMock()
    guild.get_member.return_value = None
    guild.fetch_member = AsyncMock(side_effect=discord.NotFound(MagicMock(status=404), "Not found"))
    
    author = MagicMock(spec=discord.User)
    author.id = 123
    
    cache = {}
    
    res = await cog._resolve_member(guild, author, cache)
    assert res is None
    assert cache[author.id] is None
    assert guild.fetch_member.call_count == 1

