from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock
import pytest
import discord

from bot import AntiScamBot

@pytest.fixture
def mock_config():
    return {"token": "test_token"}

@pytest.mark.asyncio
@patch("bot.AntiScamBot.tree", new_callable=PropertyMock)
async def test_bot_sync_global(mock_tree_prop, mock_config):
    mock_tree = MagicMock()
    mock_cmd = MagicMock()
    mock_cmd.name = "test_cmd"
    mock_tree.sync = AsyncMock(return_value=[mock_cmd])
    mock_tree_prop.return_value = mock_tree

    bot = AntiScamBot(mock_config, command_prefix="!", intents=discord.Intents.default())
    bot.load_extension = AsyncMock()
    
    await bot.setup_hook()
    
    mock_tree.copy_global_to.assert_not_called()
    mock_tree.sync.assert_called_once_with()
    bot.load_extension.assert_called_once_with("cogs.scam_detector")

@pytest.mark.asyncio
@patch("bot.AntiScamBot.tree", new_callable=PropertyMock)
async def test_bot_sync_guild_scoped(mock_tree_prop, mock_config):
    mock_config["sync_guild_id"] = 12345
    mock_tree = MagicMock()
    mock_cmd = MagicMock()
    mock_cmd.name = "test_cmd"
    mock_tree.sync = AsyncMock(return_value=[mock_cmd])
    mock_tree_prop.return_value = mock_tree

    bot = AntiScamBot(mock_config, command_prefix="!", intents=discord.Intents.default())
    bot.load_extension = AsyncMock()
    
    await bot.setup_hook()
    
    mock_tree.copy_global_to.assert_called_once()
    assert mock_tree.copy_global_to.call_args[1]["guild"].id == 12345
    
    mock_tree.sync.assert_called_once()
    assert mock_tree.sync.call_args[1]["guild"].id == 12345
    bot.load_extension.assert_called_once_with("cogs.scam_detector")

@pytest.mark.asyncio
@patch("bot.AntiScamBot.tree", new_callable=PropertyMock)
async def test_bot_sync_httpexception(mock_tree_prop, mock_config):
    mock_response = MagicMock()
    mock_response.status = 400
    mock_response.reason = "Bad Request"

    mock_tree = MagicMock()
    mock_tree.sync = AsyncMock(side_effect=discord.HTTPException(response=mock_response, message="test"))
    mock_tree_prop.return_value = mock_tree

    bot = AntiScamBot(mock_config, command_prefix="!", intents=discord.Intents.default())
    bot.load_extension = AsyncMock()
    
    await bot.setup_hook()
    
    mock_tree.sync.assert_called_once()
    bot.load_extension.assert_called_once_with("cogs.scam_detector")


def test_get_ignored_per_guild_keys_present():
    from bot import get_ignored_per_guild_keys
    config = {
        "token": "abc",
        "action_threshold": 5,
        "mod_log_channel_id": 123,
        "global_setting": "yes"
    }
    ignored = get_ignored_per_guild_keys(config)
    assert set(ignored) == {"action_threshold", "mod_log_channel_id"}

def test_get_ignored_per_guild_keys_none_present():
    from bot import get_ignored_per_guild_keys
    config = {
        "token": "abc",
        "prefix": "!",
        "db_path": "data/test.db",
        "sync_guild_id": 123
    }
    ignored = get_ignored_per_guild_keys(config)
    assert ignored == []

