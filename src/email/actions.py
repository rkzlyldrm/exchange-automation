"""
Email action executors — click confirmation links or extract verification codes.
"""
import logging
from typing import Optional

import aiohttp

from src.email.models import EmailMatch

logger = logging.getLogger(__name__)


async def click_confirmation_link(match: EmailMatch) -> bool:
    """Send aiohttp GET to the confirmation link, follow redirects. Return True if 2xx/3xx."""
    if not match.link:
        logger.warning(f"Email actions: no link in match '{match.watch_id}'")
        return False

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                match.link,
                allow_redirects=True,
                timeout=aiohttp.ClientTimeout(total=30),
            ) as resp:
                logger.info(f"Email actions: clicked link for '{match.watch_id}' — "
                            f"status={resp.status}, url={resp.url}")
                return resp.status < 400
    except Exception as e:
        logger.error(f"Email actions: failed to click link for '{match.watch_id}': {e}")
        return False


def extract_verification_code(match: EmailMatch) -> Optional[str]:
    """Return the extracted verification code from the match."""
    return match.code
