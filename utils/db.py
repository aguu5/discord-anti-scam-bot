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
        await self._conn.commit()

    async def close(self):
        if self._conn:
            await self._conn.close()

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
