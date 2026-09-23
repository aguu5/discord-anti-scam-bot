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


async def main():
    config = load_config()
    if not config.get("token") or config["token"] == "YOUR_TOKEN_HERE":
        raise SystemExit("You need to set the bot token in config.yaml")

    intents = discord.Intents.default()
    intents.message_content = True  # Privileged intent: enable it in the Developer Portal

    bot = commands.Bot(command_prefix=config.get("prefix", "!"), intents=intents)
    bot.config = config  # accessible from cogs via self.bot.config

    @bot.event
    async def on_ready():
        log.info("Logged in as %s (ID: %s)", bot.user, bot.user.id)
        log.info("Active in %d server(s)", len(bot.guilds))

    async with bot:
        await bot.load_extension("cogs.scam_detector")
        await bot.start(config["token"])


if __name__ == "__main__":
    asyncio.run(main())
