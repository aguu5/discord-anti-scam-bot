"""
Main cog: listens to messages, computes a risk score combining
text + links + images + behavior, and acts based on the configured thresholds.
"""
import logging
from datetime import timedelta
from typing import List, Optional

import discord
from discord.ext import commands

from utils.image_hash import add_known_hash, score_attachment_urls
from utils.link_checker import extract_urls, score_links
from utils.patterns import score_text

log = logging.getLogger("anti_scam_bot.scam_detector")


class ScamDetector(commands.Cog):
    def __init__(self, bot: commands.Bot):
        self.bot = bot
        self.cfg = bot.config
        self.db = None

    async def cog_load(self):
        from utils.db import ScamDb
        db_path = self.cfg.get("db_path", "data/bot_state.db")
        self.db = ScamDb(db_path)
        await self.db.connect()

    async def cog_unload(self):
        if self.db:
            await self.db.close()

    # ---------- helpers ----------

    def _is_new_account(self, member: discord.Member) -> bool:
        days_threshold = self.cfg.get("new_account_days_threshold", 7)
        age_days = (discord.utils.utcnow() - member.created_at).days
        return age_days < days_threshold

    def _is_exempt(self, member: discord.Member) -> bool:
        """
        Members with any of the roles listed in exempt_role_ids are skipped
        entirely: no scoring, no alert, no action. This exists so trusted
        roles (e.g. moderators) can quote or discuss scam text -- for
        warnings, documentation, etc. -- without the bot mistaking them for
        the scammer and sanctioning them.
        """
        exempt_ids = set(self.cfg.get("exempt_role_ids") or [])
        if not exempt_ids:
            return False
        member_role_ids = {role.id for role in member.roles}
        return bool(exempt_ids & member_role_ids)

    async def _register_burst(self, guild_id: int, user_id: int, has_link: bool) -> int:
        """Return extra points if the user is sending links in a burst."""
        if not has_link:
            return 0

        window = self.cfg.get("burst_window_seconds", 15)
        limit = self.cfg.get("burst_message_count", 4)
        
        count = await self.db.register_burst_and_count(guild_id, user_id, window)

        return 4 if count >= limit else 0

    async def _get_mod_log_channel(self, guild: discord.Guild):
        channel_id = self.cfg.get("mod_log_channel_id")
        if not channel_id:
            return None
        return guild.get_channel(channel_id)

    async def _send_alert(
        self,
        message: discord.Message,
        score: int,
        reasons: List[str],
        evidence_image_url: Optional[str],
    ):
        channel = await self._get_mod_log_channel(message.guild)
        if channel is None:
            log.warning("mod_log_channel_id not configured or invalid; can't send alert")
            return

        embed = discord.Embed(
            title="⚠️ Possible scam detected",
            description=(message.content or "*(no text)*")[:1000],
            color=discord.Color.orange(),
        )
        embed.add_field(name="Author", value=f"{message.author.mention} (`{message.author.id}`)", inline=False)
        embed.add_field(name="Channel", value=message.channel.mention, inline=True)
        embed.add_field(name="Score", value=str(score), inline=True)
        embed.add_field(name="Signals", value="\n".join(f"• {r}" for r in reasons) or "—", inline=False)

        # Only show the image that actually matched a known scam hash. A message
        # can carry more than one attachment, and only echoing the one that was
        # actually flagged avoids exposing moderators to unrelated content that
        # happened to ride along in the same message.
        if evidence_image_url:
            embed.set_image(url=evidence_image_url)

        embed.set_footer(text=f"Message ID: {message.id}")

        await channel.send(embed=embed)

    async def _act_on_message(
        self,
        message: discord.Message,
        score: int,
        reasons: List[str],
        evidence_image_url: Optional[str],
    ):
        await self._send_alert(message, score, reasons, evidence_image_url)

        action_threshold = self.cfg.get("action_threshold", 6)
        if score < action_threshold:
            return  # stays as an alert only, for manual review

        try:
            await message.delete()
        except discord.HTTPException:
            log.warning("Couldn't delete message %s", message.id)

        quarantine_role_id = self.cfg.get("quarantine_role_id")
        try:
            if quarantine_role_id:
                role = message.guild.get_role(quarantine_role_id)
                if role:
                    await message.author.add_roles(role, reason="Anti-scam: high-risk content")
            else:
                minutes = self.cfg.get("auto_timeout_minutes", 15)
                await message.author.timeout(timedelta(minutes=minutes), reason="Anti-scam: high-risk content")
        except discord.Forbidden:
            log.warning("Not enough permissions to sanction %s", message.author.id)

    # ---------- main listener ----------

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message):
        if message.author.bot or not message.guild:
            return

        if isinstance(message.author, discord.Member) and self._is_exempt(message.author):
            return  # trusted role: skip detection entirely

        text_score, text_reasons = score_text(message.content)
        link_score, link_reasons = score_links(message.content)

        image_urls = [
            a.url for a in message.attachments
            if a.content_type and a.content_type.startswith("image/")
        ]
        max_bytes = int(self.cfg.get("max_image_size_mb", 8) * 1024 * 1024)
        hash_score, hash_reasons, matched_image_urls = await score_attachment_urls(
            image_urls,
            hamming_threshold=self.cfg.get("hamming_threshold", 8),
            max_bytes=max_bytes,
        )

        has_link = bool(extract_urls(message.content))
        burst_score = await self._register_burst(message.guild.id, message.author.id, has_link)

        behavior_reasons = []
        if burst_score:
            behavior_reasons.append("behavior: several link messages in a short time")

        behavior_score = burst_score
        if isinstance(message.author, discord.Member) and self._is_new_account(message.author):
            behavior_score += 2
            behavior_reasons.append("behavior: recently created account")

        total_score = text_score + link_score + hash_score + behavior_score
        all_reasons = text_reasons + link_reasons + hash_reasons + behavior_reasons

        alert_threshold = self.cfg.get("alert_threshold", 3)
        if total_score >= alert_threshold:
            evidence_url = matched_image_urls[0] if matched_image_urls else None
            await self._act_on_message(message, total_score, all_reasons, evidence_url)

    # ---------- moderator commands ----------

    @commands.command(name="addhash")
    @commands.has_permissions(manage_messages=True)
    async def add_hash(self, ctx: commands.Context, label: str = "confirmed_scam"):
        """
        Reply to a message with an image (or send this command with an image
        attached) to add that image to the known scam-hashes database.
        Usage: !addhash mrbeast_casino_v3
        """
        target = None
        if ctx.message.reference:
            target = await ctx.channel.fetch_message(ctx.message.reference.message_id)
        elif ctx.message.attachments:
            target = ctx.message

        if not target or not target.attachments:
            await ctx.reply("Reply to a message with an image, or attach an image along with the command.")
            return

        added_urls = []
        for att in target.attachments:
            if att.content_type and att.content_type.startswith("image/"):
                if await add_known_hash(att.url, label):
                    added_urls.append(att.url)

        await ctx.reply(f"✅ Added {len(added_urls)} image(s) to the database with label `{label}`.")

        if added_urls:
            await self._log_hash_addition(ctx, label, added_urls)

    async def _log_hash_addition(self, ctx: commands.Context, label: str, image_urls: List[str]):
        """
        Post an audit entry to the mod-log channel every time !addhash is used.
        This makes hash additions traceable: if a compromised or careless mod
        account ever adds something it shouldn't, there's a record of who did
        it and when, instead of a silent, unattributed change to the database.
        """
        channel = await self._get_mod_log_channel(ctx.guild)
        if channel is None:
            return

        embed = discord.Embed(
            title="Scam hash added",
            description=f"{len(image_urls)} image(s) added with label `{label}`",
            color=discord.Color.blue(),
        )
        embed.add_field(name="Added by", value=f"{ctx.author.mention} (`{ctx.author.id}`)", inline=False)
        embed.set_image(url=image_urls[0])
        embed.set_footer(text="Anti-scam audit log")
        await channel.send(embed=embed)

    @commands.command(name="scamconfig")
    @commands.has_permissions(manage_guild=True)
    async def show_config(self, ctx: commands.Context):
        """Show the active thresholds (to verify the config loaded correctly)."""
        cfg = self.cfg
        lines = [
            f"action_threshold: {cfg.get('action_threshold')}",
            f"alert_threshold: {cfg.get('alert_threshold')}",
            f"hamming_threshold: {cfg.get('hamming_threshold')}",
            f"mod_log_channel_id: {cfg.get('mod_log_channel_id')}",
            f"exempt_role_ids: {cfg.get('exempt_role_ids')}",
            f"max_image_size_mb: {cfg.get('max_image_size_mb')}",
        ]
        await ctx.reply("```\n" + "\n".join(lines) + "\n```")


async def setup(bot: commands.Bot):
    await bot.add_cog(ScamDetector(bot))
