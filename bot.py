"""
Discord anti-scam bot (MrBeast / crypto-casino and similar scams).
Main entry point.
"""
import asyncio
import logging

import discord
import yaml
from discord.ext import commands

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("anti_scam_bot")


def load_config(path: str = "config.yaml") -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        raise SystemExit(
            f"Couldn't find '{path}'. Copy config.example.yaml to config.yaml "
            "and fill in the values (especially the token)."
        )


class AntiScamBot(commands.Bot):
    def __init__(self, config, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.config = config

    async def setup_hook(self):
        await self.load_extension("cogs.scam_detector")
        
        sync_guild_id = self.config.get("sync_guild_id")
        try:
            if sync_guild_id:
                guild = discord.Object(id=sync_guild_id)
                self.tree.copy_global_to(guild=guild)
                synced = await self.tree.sync(guild=guild)
                log.info("Synced %d command(s) to guild %s: %s", len(synced), sync_guild_id, [c.name for c in synced])
            else:
                synced = await self.tree.sync()
                log.info("Synced %d command(s) globally: %s", len(synced), [c.name for c in synced])
        except discord.HTTPException:
            log.exception("Failed to sync commands (HTTPException).")

    async def on_ready(self):
        log.info("Logged in as %s (ID: %s)", self.user, self.user.id)
        log.info("Active in %d server(s)", len(self.guilds))


def get_ignored_per_guild_keys(config: dict) -> list[str]:
    per_guild_keys = {
        "action_threshold", "alert_threshold", "hamming_threshold",
        "mod_log_channel_id", "exempt_role_ids", "max_image_size_mb",
        "new_account_days_threshold", "burst_message_count", "burst_window_seconds",
        "auto_timeout_minutes", "quarantine_role_id", "dm_on_action",
        "dm_message", "suspicious_domain_age_days"
    }
    return [k for k in config if k in per_guild_keys]


async def main():
    config = load_config()
    if not config.get("token") or config["token"] == "YOUR_TOKEN_HERE":
        raise SystemExit("You need to set the bot token in config.yaml")

    ignored_keys = get_ignored_per_guild_keys(config)
    if ignored_keys:
        log.warning(
            "The following per-guild settings were found in config.yaml and will be IGNORED: %s. "
            "These must be set per-server using the /scamconfig commands.",
            ", ".join(ignored_keys)
        )

    intents = discord.Intents.default()
    intents.message_content = True  # Privileged intent: enable it in the Developer Portal

    bot = AntiScamBot(config, command_prefix=config.get("prefix", "!"), intents=intents)

    async with bot:
        await bot.start(config["token"])


if __name__ == "__main__":
    asyncio.run(main())
