import time
import aiosqlite

class ScamDb:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._conn = None

    async def connect(self):
        self._conn = await aiosqlite.connect(self.db_path)
        await self._init_db()

    async def _init_db(self):
        await self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS burst_history (
                guild_id INTEGER,
                user_id INTEGER,
                timestamp REAL
            )
            """
        )
        await self._conn.execute("CREATE INDEX IF NOT EXISTS idx_burst_history ON burst_history(guild_id, user_id)")
        
        await self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS guild_settings (
                guild_id INTEGER PRIMARY KEY,
                action_threshold INTEGER DEFAULT 6,
                alert_threshold INTEGER DEFAULT 3,
                hamming_threshold INTEGER DEFAULT 8,
                mod_log_channel_id INTEGER,
                exempt_role_ids TEXT,
                max_image_size_mb INTEGER DEFAULT 8,
                new_account_days_threshold INTEGER DEFAULT 7,
                burst_message_count INTEGER DEFAULT 4,
                burst_window_seconds INTEGER DEFAULT 15,
                auto_timeout_minutes INTEGER DEFAULT 15,
                quarantine_role_id INTEGER
            )
            """
        )
        await self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS guild_stats (
                guild_id INTEGER PRIMARY KEY,
                messages_scored INTEGER DEFAULT 0,
                alerts_raised INTEGER DEFAULT 0,
                actions_taken INTEGER DEFAULT 0
            )
            """
        )
        await self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS whois_cache (
                domain TEXT PRIMARY KEY,
                creation_date REAL,
                lookup_time REAL
            )
            """
        )
        
        # 10.10 migration: Add missing columns if they don't exist
        for col, col_def in [
            ("dm_on_action", "INTEGER DEFAULT 1"),
            ("dm_message", "TEXT"),
            ("suspicious_domain_age_days", "INTEGER DEFAULT 30")
        ]:
            try:
                await self._conn.execute(f"ALTER TABLE guild_settings ADD COLUMN {col} {col_def}")
            except aiosqlite.OperationalError:
                pass # Column already exists
                
        await self._conn.commit()

    async def close(self):
        if self._conn:
            await self._conn.close()

    async def get_guild_config(self, guild_id: int) -> dict:
        async with self._conn.execute(
            "SELECT action_threshold, alert_threshold, hamming_threshold, mod_log_channel_id, exempt_role_ids, max_image_size_mb, new_account_days_threshold, burst_message_count, burst_window_seconds, auto_timeout_minutes, quarantine_role_id, dm_on_action, dm_message, suspicious_domain_age_days FROM guild_settings WHERE guild_id = ?",
            (guild_id,)
        ) as cursor:
            row = await cursor.fetchone()
            if row:
                return {
                    "action_threshold": row[0],
                    "alert_threshold": row[1],
                    "hamming_threshold": row[2],
                    "mod_log_channel_id": row[3],
                    "exempt_role_ids": [int(x) for x in row[4].split(",")] if row[4] else [],
                    "max_image_size_mb": row[5],
                    "new_account_days_threshold": row[6],
                    "burst_message_count": row[7],
                    "burst_window_seconds": row[8],
                    "auto_timeout_minutes": row[9],
                    "quarantine_role_id": row[10],
                    "dm_on_action": bool(row[11]) if row[11] is not None else True,
                    "dm_message": row[12],
                    "suspicious_domain_age_days": row[13] if row[13] is not None else 30,
                }
            
            # Default fallback
            await self._conn.execute(
                "INSERT INTO guild_settings (guild_id) VALUES (?)",
                (guild_id,)
            )
            await self._conn.commit()
            return await self.get_guild_config(guild_id)

    async def update_guild_config(self, guild_id: int, key: str, value):
        if key == "exempt_role_ids" and isinstance(value, list):
            value = ",".join(str(x) for x in value)
        await self._conn.execute(
            f"UPDATE guild_settings SET {key} = ? WHERE guild_id = ?",
            (value, guild_id)
        )
        await self._conn.commit()

    async def register_burst_and_count(self, guild_id: int, user_id: int, window_seconds: int) -> int:
        """
        Registers a burst link message and returns the number of link messages in the window.
        """
        now = time.time()
        cutoff = now - window_seconds
        
        # Prune old entries
        await self._conn.execute(
            "DELETE FROM burst_history WHERE guild_id = ? AND user_id = ? AND timestamp <= ?",
            (guild_id, user_id, cutoff)
        )
        
        # Add new entry
        await self._conn.execute(
            "INSERT INTO burst_history (guild_id, user_id, timestamp) VALUES (?, ?, ?)",
            (guild_id, user_id, now)
        )
        
        await self._conn.commit()
        
        # Count remaining
        async with self._conn.execute(
            "SELECT COUNT(*) FROM burst_history WHERE guild_id = ? AND user_id = ?",
            (guild_id, user_id)
        ) as cursor:
            row = await cursor.fetchone()
            return row[0] if row else 0

    async def increment_stat(self, guild_id: int, stat: str):
        valid_stats = {"messages_scored", "alerts_raised", "actions_taken"}
        if stat not in valid_stats:
            return
        await self._conn.execute(
            "INSERT OR IGNORE INTO guild_stats (guild_id) VALUES (?)",
            (guild_id,)
        )
        await self._conn.execute(
            f"UPDATE guild_stats SET {stat} = {stat} + 1 WHERE guild_id = ?",
            (guild_id,)
        )
        await self._conn.commit()

    async def get_guild_stats(self, guild_id: int) -> dict:
        async with self._conn.execute(
            "SELECT messages_scored, alerts_raised, actions_taken FROM guild_stats WHERE guild_id = ?",
            (guild_id,)
        ) as cursor:
            row = await cursor.fetchone()
            if row:
                return {
                    "messages_scored": row[0],
                    "alerts_raised": row[1],
                    "actions_taken": row[2]
                }
            return {"messages_scored": 0, "alerts_raised": 0, "actions_taken": 0}

    async def get_whois_cache(self, domain: str):
        async with self._conn.execute(
            "SELECT creation_date FROM whois_cache WHERE domain = ?",
            (domain,)
        ) as cursor:
            row = await cursor.fetchone()
            if row:
                return row[0]
            return None

    async def set_whois_cache(self, domain: str, creation_date: float | None):
        await self._conn.execute(
            "INSERT OR REPLACE INTO whois_cache (domain, creation_date, lookup_time) VALUES (?, ?, ?)",
            (domain, creation_date, time.time())
        )
        await self._conn.commit()
