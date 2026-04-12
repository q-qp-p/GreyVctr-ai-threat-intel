"""
AI Shield Intelligence - Processing State Manager
Manages processing pause/resume state using Redis
"""
import logging
from datetime import datetime, timezone
from typing import Optional

import redis.asyncio as aioredis

from config import settings

logger = logging.getLogger(__name__)


class ProcessingStateManager:
    """
    Manages processing pause/resume state in Redis.

    This class provides async methods for:
    - Checking if processing is currently paused
    - Setting the pause state with metadata (timestamp, username)
    - Retrieving full pause info (paused, paused_at, paused_by)

    The pause state is stored in Redis so it survives API restarts
    and is visible to all Celery workers.
    """

    # Redis key constants
    KEY_PAUSED = "processing:paused"
    KEY_PAUSED_AT = "processing:paused_at"
    KEY_PAUSED_BY = "processing:paused_by"

    def __init__(self, redis_url: Optional[str] = None):
        """
        Initialize the ProcessingStateManager.

        Args:
            redis_url: Redis connection URL. If None, uses settings.redis_url
        """
        self.redis_url = redis_url or settings.redis_url
        self._redis_client: Optional[aioredis.Redis] = None

    async def _get_redis_client(self) -> aioredis.Redis:
        """
        Get or create Redis client with connection pooling.

        Returns:
            Redis client instance
        """
        if self._redis_client is None:
            self._redis_client = aioredis.from_url(
                self.redis_url,
                decode_responses=True,
                encoding="utf-8"
            )
        return self._redis_client

    async def close(self):
        """Close Redis connection and cleanup resources."""
        if self._redis_client is not None:
            await self._redis_client.close()
            self._redis_client = None

    async def is_paused(self) -> bool:
        """
        Check if processing is currently paused.

        Returns:
            True if processing is paused, False otherwise.
            Defaults to False if the key does not exist in Redis.

        Raises:
            Exception: If Redis operation fails
        """
        try:
            redis_client = await self._get_redis_client()
            value = await redis_client.get(self.KEY_PAUSED)

            if value is None:
                logger.debug("No pause state found in Redis, defaulting to not paused")
                return False

            paused = value.lower() == "true"
            logger.debug(f"Processing paused state: {paused}")
            return paused

        except Exception as e:
            logger.error(f"Failed to get pause state from Redis: {e}")
            raise

    async def set_paused(self, paused: bool, username: Optional[str] = None) -> None:
        """
        Set the processing pause state.

        When pausing (paused=True), stores the timestamp and username.
        When resuming (paused=False), removes the paused_at and paused_by keys.

        Args:
            paused: True to pause processing, False to resume
            username: Username of the admin performing the action

        Raises:
            Exception: If Redis operation fails
        """
        try:
            redis_client = await self._get_redis_client()

            if paused:
                timestamp = datetime.now(timezone.utc).isoformat()
                await redis_client.set(self.KEY_PAUSED, "true")
                await redis_client.set(self.KEY_PAUSED_AT, timestamp)
                if username:
                    await redis_client.set(self.KEY_PAUSED_BY, username)
                logger.info(f"Processing paused by {username} at {timestamp}")
            else:
                await redis_client.set(self.KEY_PAUSED, "false")
                await redis_client.delete(self.KEY_PAUSED_AT)
                await redis_client.delete(self.KEY_PAUSED_BY)
                logger.info("Processing resumed")

        except Exception as e:
            logger.error(f"Failed to set pause state in Redis: {e}")
            raise

    async def get_pause_info(self) -> dict:
        """
        Get full pause state information.

        Returns:
            Dictionary with:
                - paused (bool): Whether processing is paused
                - paused_at (str | None): ISO 8601 timestamp when paused
                - paused_by (str | None): Username who paused processing

        Raises:
            Exception: If Redis operation fails
        """
        try:
            redis_client = await self._get_redis_client()

            paused_value = await redis_client.get(self.KEY_PAUSED)
            paused = paused_value is not None and paused_value.lower() == "true"

            paused_at = await redis_client.get(self.KEY_PAUSED_AT) if paused else None
            paused_by = await redis_client.get(self.KEY_PAUSED_BY) if paused else None

            return {
                "paused": paused,
                "paused_at": paused_at,
                "paused_by": paused_by,
            }

        except Exception as e:
            logger.error(f"Failed to get pause info from Redis: {e}")
            raise


# Global instance for easy access
_processing_state_manager: Optional[ProcessingStateManager] = None


def get_processing_state_manager() -> ProcessingStateManager:
    """
    Get or create the global ProcessingStateManager instance.

    Returns:
        ProcessingStateManager instance
    """
    global _processing_state_manager
    if _processing_state_manager is None:
        _processing_state_manager = ProcessingStateManager()
    return _processing_state_manager


async def close_processing_state_manager():
    """Close the global ProcessingStateManager instance."""
    global _processing_state_manager
    if _processing_state_manager is not None:
        await _processing_state_manager.close()
        _processing_state_manager = None
