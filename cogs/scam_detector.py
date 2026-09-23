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
from utils.ocr import extract_text
from utils.patterns import score_text

log = logging.getLogger("anti_scam_bot.scam_detector")


class UndoActionView(discord.ui.View):
    def __init__(self, target_id: int, quarantine_role_id: Optional[int]):
        super().__init__(timeout=None)
        self.target_id = target_id
        self.quarantine_role_id = quarantine_role_id

    @discord.ui.button(label="Undo Action", style=discord.ButtonStyle.green)
    async def undo_action(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not interaction.user.guild_permissions.manage_messages:
            await interaction.response.send_message("You don't have permission to use this button.", ephemeral=True)
            return

        member = interaction.guild.get_member(self.target_id)
        if not member:
            await interaction.response.send_message("User is no longer in the server.", ephemeral=True)
            return

        try:
            if self.quarantine_role_id:
                role = interaction.guild.get_role(self.quarantine_role_id)
                if role and role in member.roles:
                    await member.remove_roles(role, reason=f"Action undone by {interaction.user}")
            else:
                if member.is_timed_out():
                    await member.timeout(None, reason=f"Action undone by {interaction.user}")
            
            button.disabled = True
            button.label = f"Undone by {interaction.user.display_name}"
            await interaction.response.edit_message(view=self)
        except discord.Forbidden:
            await interaction.response.send_message("I lack permissions to undo the sanction.", ephemeral=True)
        except Exception as e:
            await interaction.response.send_message(f"Error undoing action: {e}", ephemeral=True)


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

    def _is_new_account(self, member: discord.Member, guild_cfg: dict) -> bool:
        days_threshold = guild_cfg.get("new_account_days_threshold", 7)
        age_days = (discord.utils.utcnow() - member.created_at).days
        return age_days < days_threshold

    def _is_exempt(self, member: discord.Member, guild_cfg: dict) -> bool:
        """
        Members with any of the roles listed in exempt_role_ids are skipped
        entirely: no scoring, no alert, no action. This exists so trusted
        roles (e.g. moderators) can quote or discuss scam text -- for
        warnings, documentation, etc. -- without the bot mistaking them for
        the scammer and sanctioning them.
        """
        exempt_ids = set(guild_cfg.get("exempt_role_ids") or [])
        if not exempt_ids:
            return False
        member_role_ids = {role.id for role in member.roles}
        return bool(exempt_ids & member_role_ids)

    async def _register_burst(self, guild_id: int, user_id: int, has_link: bool, guild_cfg: dict) -> int:
        """Return extra points if the user is sending links in a burst."""
        if not has_link:
            return 0

        window = guild_cfg.get("burst_window_seconds", 15)
        limit = guild_cfg.get("burst_message_count", 4)
        
        count = await self.db.register_burst_and_count(guild_id, user_id, window)

        return 4 if count >= limit else 0

    async def _get_mod_log_channel(self, guild: discord.Guild, guild_cfg: dict):
        channel_id = guild_cfg.get("mod_log_channel_id")
        if not channel_id:
            return None
        return guild.get_channel(channel_id)

    async def _send_alert(
        self,
        message: discord.Message,
        score: int,
        reasons: List[str],
        evidence_image_url: Optional[str],
        guild_cfg: dict,
        view: Optional[discord.ui.View] = discord.utils.MISSING,
    ):
        channel = await self._get_mod_log_channel(message.guild, guild_cfg)
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

        await channel.send(embed=embed, view=view)

    async def _act_on_message(
        self,
        message: discord.Message,
        score: int,
        reasons: List[str],
        evidence_image_url: Optional[str],
        guild_cfg: dict,
    ):
        action_threshold = guild_cfg.get("action_threshold", 6)
        if score < action_threshold:
            await self._send_alert(message, score, reasons, evidence_image_url, guild_cfg)
            await self.db.increment_stat(message.guild.id, "alerts_raised")
            return  # stays as an alert only, for manual review

        quarantine_role_id = guild_cfg.get("quarantine_role_id")
        view = UndoActionView(message.author.id, quarantine_role_id)
        await self._send_alert(message, score, reasons, evidence_image_url, guild_cfg, view)
        await self.db.increment_stat(message.guild.id, "alerts_raised")
        await self.db.increment_stat(message.guild.id, "actions_taken")

        try:
            await message.delete()
        except discord.HTTPException:
            log.warning("Couldn't delete message %s", message.id)

        # Send DM before sanctioning
        dm_on_action = self.cfg.get("dm_on_action", True)
        if dm_on_action:
            dm_msg = self.cfg.get(
                "dm_message", 
                "Your account was flagged for suspicious activity and has been temporarily restricted. Please check your authorized apps, change your password, and enable 2FA."
            )
            try:
                await message.author.send(dm_msg)
            except discord.Forbidden:
                log.warning("Forbidden: Could not DM user %s before sanctioning", message.author.id)
            except discord.HTTPException as e:
                log.warning("HTTPException trying to DM user %s: %s", message.author.id, e)

        try:
            if quarantine_role_id:
                role = message.guild.get_role(quarantine_role_id)
                if role:
                    await message.author.add_roles(role, reason="Anti-scam: high-risk content")
            else:
                minutes = guild_cfg.get("auto_timeout_minutes", 15)
                await message.author.timeout(timedelta(minutes=minutes), reason="Anti-scam: high-risk content")
        except discord.Forbidden:
            log.warning("Not enough permissions to sanction %s", message.author.id)

    # ---------- main listener ----------

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message):
        if message.author.bot or not message.guild:
            return
        guild_cfg = await self.db.get_guild_config(message.guild.id)
        if isinstance(message.author, discord.Member) and self._is_exempt(message.author, guild_cfg):
            return  # trusted role: skip detection entirely

        await self.db.increment_stat(message.guild.id, "messages_scored")

        text_score, text_reasons = score_text(message.content)
        link_score, link_reasons = score_links(message.content)

        image_urls = [
            a.url for a in message.attachments
            if a.content_type and a.content_type.startswith("image/")
        ]
        max_bytes = int(guild_cfg.get("max_image_size_mb", 8) * 1024 * 1024)
        hash_score, hash_reasons, matched_image_urls, unmatched_images = await score_attachment_urls(
            image_urls,
            hamming_threshold=guild_cfg.get("hamming_threshold", 8),
            max_bytes=max_bytes,
        )

        ocr_score = 0
        ocr_reasons = []
        for url, raw_bytes in unmatched_images:
            extracted = await extract_text(raw_bytes)
            if extracted:
                t_score, t_reasons = score_text(extracted)
                ocr_score += t_score
                for r in t_reasons:
                    ocr_reasons.append(r.replace("text: ", "image (OCR): ", 1))

        has_link = bool(extract_urls(message.content))
        burst_score = await self._register_burst(message.guild.id, message.author.id, has_link, guild_cfg)

        behavior_reasons = []
        if burst_score:
            behavior_reasons.append("behavior: several link messages in a short time")

        behavior_score = burst_score
        if isinstance(message.author, discord.Member) and self._is_new_account(message.author, guild_cfg):
            behavior_score += 2
            behavior_reasons.append("behavior: recently created account")

        total_score = text_score + link_score + hash_score + ocr_score + behavior_score
        all_reasons = text_reasons + link_reasons + hash_reasons + ocr_reasons + behavior_reasons

        alert_threshold = guild_cfg.get("alert_threshold", 3)
        if total_score >= alert_threshold:
            evidence_url = matched_image_urls[0] if matched_image_urls else None
            await self._act_on_message(message, total_score, all_reasons, evidence_url, guild_cfg)

    # ---------- moderator commands ----------

    @discord.app_commands.command(name="addhash", description="Add an image to the known scam-hashes database.")
    @discord.app_commands.describe(
        image="The image to add to the database",
        label="The label for the known scam hash (default: confirmed_scam)"
    )
    @discord.app_commands.default_permissions(manage_messages=True)
    async def add_hash(self, interaction: discord.Interaction, image: discord.Attachment, label: str = "confirmed_scam"):
        if not image.content_type or not image.content_type.startswith("image/"):
            await interaction.response.send_message("The attached file must be an image.", ephemeral=True)
            return
            
        await interaction.response.defer(ephemeral=True)

        added = await add_known_hash(image.url, label)
        if added:
            await interaction.followup.send(f"✅ Added image to the database with label `{label}`.")
            
            # Create a mock ctx-like object for _log_hash_addition or adapt it
            class MockCtx:
                def __init__(self, interaction):
                    self.guild = interaction.guild
                    self.author = interaction.user
            
            await self._log_hash_addition(MockCtx(interaction), label, [image.url])
        else:
            await interaction.followup.send("Failed to add image or it is already known.")

    async def _log_hash_addition(self, ctx: commands.Context, label: str, image_urls: List[str]):
        """
        Post an audit entry to the mod-log channel every time !addhash is used.
        This makes hash additions traceable: if a compromised or careless mod
        account ever adds something it shouldn't, there's a record of who did
        it and when, instead of a silent, unattributed change to the database.
        """
        guild_cfg = await self.db.get_guild_config(ctx.guild.id)
        channel = await self._get_mod_log_channel(ctx.guild, guild_cfg)
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

    config_group = discord.app_commands.Group(
        name="scamconfig", 
        description="Configure anti-scam settings for this server",
        default_permissions=discord.Permissions(manage_guild=True)
    )

    @config_group.command(name="view", description="Show the active config for this server.")
    async def config_view(self, interaction: discord.Interaction):
        guild_cfg = await self.db.get_guild_config(interaction.guild_id)
        lines = [
            f"action_threshold: {guild_cfg.get('action_threshold')}",
            f"alert_threshold: {guild_cfg.get('alert_threshold')}",
            f"hamming_threshold: {guild_cfg.get('hamming_threshold')}",
            f"mod_log_channel_id: {guild_cfg.get('mod_log_channel_id')}",
            f"exempt_role_ids: {guild_cfg.get('exempt_role_ids')}",
            f"max_image_size_mb: {guild_cfg.get('max_image_size_mb')}",
            f"new_account_days_threshold: {guild_cfg.get('new_account_days_threshold')}",
            f"burst_message_count: {guild_cfg.get('burst_message_count')}",
            f"burst_window_seconds: {guild_cfg.get('burst_window_seconds')}",
            f"auto_timeout_minutes: {guild_cfg.get('auto_timeout_minutes')}",
            f"quarantine_role_id: {guild_cfg.get('quarantine_role_id')}",
        ]
        await interaction.response.send_message("```\n" + "\n".join(lines) + "\n```", ephemeral=True)

    @config_group.command(name="set", description="Set a configuration value.")
    @discord.app_commands.describe(
        action_threshold="Action threshold score",
        alert_threshold="Alert threshold score",
        hamming_threshold="Hamming distance threshold for image hashes",
        mod_log_channel="Channel for moderator alerts",
        max_image_size_mb="Max image size to process (MB)",
        new_account_days="Days threshold to consider an account 'new'",
        burst_message_count="Number of link messages in window to trigger burst",
        burst_window="Window in seconds for burst detection",
        auto_timeout="Minutes to timeout user automatically",
        quarantine_role="Role to assign for quarantine"
    )
    async def config_set(
        self, 
        interaction: discord.Interaction,
        action_threshold: Optional[int] = None,
        alert_threshold: Optional[int] = None,
        hamming_threshold: Optional[int] = None,
        mod_log_channel: Optional[discord.TextChannel] = None,
        max_image_size_mb: Optional[int] = None,
        new_account_days: Optional[int] = None,
        burst_message_count: Optional[int] = None,
        burst_window: Optional[int] = None,
        auto_timeout: Optional[int] = None,
        quarantine_role: Optional[discord.Role] = None,
    ):
        updated = []
        if action_threshold is not None:
            await self.db.update_guild_config(interaction.guild_id, "action_threshold", action_threshold)
            updated.append("action_threshold")
        if alert_threshold is not None:
            await self.db.update_guild_config(interaction.guild_id, "alert_threshold", alert_threshold)
            updated.append("alert_threshold")
        if hamming_threshold is not None:
            await self.db.update_guild_config(interaction.guild_id, "hamming_threshold", hamming_threshold)
            updated.append("hamming_threshold")
        if mod_log_channel is not None:
            await self.db.update_guild_config(interaction.guild_id, "mod_log_channel_id", mod_log_channel.id)
            updated.append("mod_log_channel_id")
        if max_image_size_mb is not None:
            await self.db.update_guild_config(interaction.guild_id, "max_image_size_mb", max_image_size_mb)
            updated.append("max_image_size_mb")
        if new_account_days is not None:
            await self.db.update_guild_config(interaction.guild_id, "new_account_days_threshold", new_account_days)
            updated.append("new_account_days_threshold")
        if burst_message_count is not None:
            await self.db.update_guild_config(interaction.guild_id, "burst_message_count", burst_message_count)
            updated.append("burst_message_count")
        if burst_window is not None:
            await self.db.update_guild_config(interaction.guild_id, "burst_window_seconds", burst_window)
            updated.append("burst_window_seconds")
        if auto_timeout is not None:
            await self.db.update_guild_config(interaction.guild_id, "auto_timeout_minutes", auto_timeout)
            updated.append("auto_timeout_minutes")
        if quarantine_role is not None:
            await self.db.update_guild_config(interaction.guild_id, "quarantine_role_id", quarantine_role.id)
            updated.append("quarantine_role_id")
            
        if updated:
            await interaction.response.send_message(f"Updated configuration for: {', '.join(updated)}", ephemeral=True)
        else:
            await interaction.response.send_message("No configuration changes provided.", ephemeral=True)

    @config_group.command(name="add_exempt_role", description="Add an exempt role")
    async def config_add_exempt(self, interaction: discord.Interaction, role: discord.Role):
        cfg = await self.db.get_guild_config(interaction.guild_id)
        roles = cfg.get("exempt_role_ids") or []
        if role.id not in roles:
            roles.append(role.id)
            await self.db.update_guild_config(interaction.guild_id, "exempt_role_ids", roles)
            await interaction.response.send_message(f"Added {role.mention} to exempt roles.", ephemeral=True)
        else:
            await interaction.response.send_message(f"{role.mention} is already exempt.", ephemeral=True)
            
    @config_group.command(name="remove_exempt_role", description="Remove an exempt role")
    async def config_remove_exempt(self, interaction: discord.Interaction, role: discord.Role):
        cfg = await self.db.get_guild_config(interaction.guild_id)
        roles = cfg.get("exempt_role_ids") or []
        if role.id in roles:
            roles.remove(role.id)
            await self.db.update_guild_config(interaction.guild_id, "exempt_role_ids", roles)
            await interaction.response.send_message(f"Removed {role.mention} from exempt roles.", ephemeral=True)
        else:
            await interaction.response.send_message(f"{role.mention} is not exempt.", ephemeral=True)

    @discord.app_commands.command(name="stats", description="Show scam detection statistics for this server.")
    @discord.app_commands.default_permissions(manage_guild=True)
    async def show_stats(self, interaction: discord.Interaction):
        stats = await self.db.get_guild_stats(interaction.guild_id)
        embed = discord.Embed(title="Scam Detection Stats", color=discord.Color.blurple())
        embed.add_field(name="Messages Scored", value=str(stats.get("messages_scored", 0)))
        embed.add_field(name="Alerts Raised", value=str(stats.get("alerts_raised", 0)))
        embed.add_field(name="Actions Taken", value=str(stats.get("actions_taken", 0)))
        await interaction.response.send_message(embed=embed, ephemeral=True)

    @discord.app_commands.command(name="scan", description="Retroactively score the last N messages in the channel.")
    @discord.app_commands.describe(limit="Number of messages to scan (default 100, max 500)")
    @discord.app_commands.default_permissions(manage_messages=True)
    async def scan_channel(self, interaction: discord.Interaction, limit: int = 100):
        if limit < 1:
            limit = 100
        if limit > 500:
            limit = 500

        await interaction.response.defer(ephemeral=True)
        
        guild_cfg = await self.db.get_guild_config(interaction.guild_id)
        scanned = 0
        flagged = 0

        async for msg in interaction.channel.history(limit=limit):
            if msg.author.bot or not msg.guild:
                continue
            if isinstance(msg.author, discord.Member) and self._is_exempt(msg.author, guild_cfg):
                continue
                
            await self.db.increment_stat(interaction.guild_id, "messages_scored")
            scanned += 1

            text_score, text_reasons = score_text(msg.content)
            link_score, link_reasons = score_links(msg.content)

            image_urls = [
                a.url for a in msg.attachments
                if a.content_type and a.content_type.startswith("image/")
            ]
            max_bytes = int(guild_cfg.get("max_image_size_mb", 8) * 1024 * 1024)
            hash_score, hash_reasons, matched_image_urls, unmatched_images = await score_attachment_urls(
                image_urls,
                hamming_threshold=guild_cfg.get("hamming_threshold", 8),
                max_bytes=max_bytes,
            )

            ocr_score = 0
            ocr_reasons = []
            for url, raw_bytes in unmatched_images:
                extracted = await extract_text(raw_bytes)
                if extracted:
                    t_score, t_reasons = score_text(extracted)
                    ocr_score += t_score
                    for r in t_reasons:
                        ocr_reasons.append(r.replace("text: ", "image (OCR): ", 1))

            total_score = text_score + link_score + hash_score + ocr_score
            all_reasons = text_reasons + link_reasons + hash_reasons + ocr_reasons

            alert_threshold = guild_cfg.get("alert_threshold", 3)
            if total_score >= alert_threshold:
                evidence_url = matched_image_urls[0] if matched_image_urls else None
                await self._act_on_message(msg, total_score, all_reasons, evidence_url, guild_cfg)
                flagged += 1

        await interaction.followup.send(f"Scan complete. Scanned {scanned} messages, flagged {flagged}.")

async def setup(bot: commands.Bot):
    await bot.add_cog(ScamDetector(bot))
