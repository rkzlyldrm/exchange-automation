"""
Per-exchange browser session — wraps a BrowserContext with login state,
token capture, and concurrency locking.
"""
import asyncio
import time
import logging
from typing import Optional, Dict, Any

from playwright.async_api import BrowserContext, Page

from src.browser.manager import browser_manager

logger = logging.getLogger(__name__)


class ExchangeSession:
    """
    Manages a single exchange's browser session inside its BrowserContext.

    - Provides an asyncio.Lock so only one operation runs at a time per exchange
    - Tracks login state, captured tokens, and errors
    - Auto-relogin before operations if session expired
    """

    def __init__(self, exchange_name: str):
        self.exchange_name = exchange_name
        self.lock = asyncio.Lock()

        # Session state
        self.is_logged_in: bool = False
        self.last_login_at: Optional[float] = None
        self.last_error: Optional[str] = None
        self.status: str = "disconnected"  # connected / disconnected / logging_in / error / waiting_for_captcha / waiting_for_email_approval

        # Captured auth data (exchange-specific)
        self.captured_tokens: Dict[str, Any] = {}

        # Captcha solving: login flow sets this event when captcha is resolved
        self._captcha_event: Optional[asyncio.Event] = None

        # Verification codes: login flow waits, submit-verification endpoint fills + unblocks
        self._verification_event: Optional[asyncio.Event] = None
        self.verification_codes: Dict[str, str] = {}  # {email_code, sms_code}

        # Page reference (main page for this exchange)
        self._page: Optional[Page] = None
        self._context: Optional[BrowserContext] = None

    # ── context / page helpers ─────────────────────────────────

    async def get_context(self) -> BrowserContext:
        """Get (or create) the BrowserContext for this exchange."""
        if self._context is None:
            self._context = await browser_manager.get_context(self.exchange_name)
        return self._context

    async def get_page(self) -> Page:
        """Get (or create) the main page for this exchange."""
        if self._page is None or self._page.is_closed():
            ctx = await self.get_context()
            self._page = await ctx.new_page()
        return self._page

    async def close(self) -> None:
        """Close page and context."""
        if self._page and not self._page.is_closed():
            try:
                await self._page.close()
            except Exception:
                pass
        self._page = None
        self._context = None
        self.is_logged_in = False
        self.status = "disconnected"
        self.captured_tokens.clear()

    # ── state management ───────────────────────────────────────

    def set_logged_in(self, tokens: Optional[Dict[str, Any]] = None) -> None:
        self.is_logged_in = True
        self.last_login_at = time.time()
        self.last_error = None
        self.status = "connected"
        if tokens:
            self.captured_tokens.update(tokens)

    def set_error(self, error: str) -> None:
        self.is_logged_in = False
        self.last_error = error
        self.status = "error"

    def get_status(self) -> dict:
        """Return serializable status dict."""
        current_url = None
        try:
            if self._page and not self._page.is_closed():
                current_url = self._page.url
        except Exception:
            pass
        return {
            "exchange_name": self.exchange_name,
            "status": self.status,
            "is_logged_in": self.is_logged_in,
            "last_login_at": self.last_login_at,
            "last_error": self.last_error,
            "has_token": bool(self.get_auth_token()),
            "current_url": current_url,
        }

    # ── token access ───────────────────────────────────────────

    # Token keys checked in order of priority
    _TOKEN_KEYS = ("authorization", "bt_newsessionid", "cid")

    def get_auth_token(self) -> Optional[str]:
        """Return the captured auth token (checks exchange-specific keys)."""
        for key in self._TOKEN_KEYS:
            val = self.captured_tokens.get(key)
            if val:
                return val
        return None

    # ── captcha helpers ─────────────────────────────────────────

    async def wait_for_captcha_solved(self, timeout: float = 120) -> bool:
        """Block login flow until human solves captcha or timeout."""
        self.status = "waiting_for_captcha"
        self._captcha_event = asyncio.Event()
        logger.info(f"{self.exchange_name}: waiting for human captcha solve (timeout={timeout}s)")
        try:
            await asyncio.wait_for(self._captcha_event.wait(), timeout=timeout)
            logger.info(f"{self.exchange_name}: captcha resolved by human")
            return True
        except asyncio.TimeoutError:
            logger.warning(f"{self.exchange_name}: captcha solve timed out after {timeout}s")
            return False
        finally:
            self._captcha_event = None

    def notify_captcha_solved(self) -> None:
        """Called by click-forwarding endpoint after human clicks resolve captcha."""
        if self._captcha_event:
            self._captcha_event.set()

    # ── verification helpers ─────────────────────────────────

    async def wait_for_verification_codes(self, timeout: float = 300) -> bool:
        """Block login flow until user submits verification codes or timeout."""
        self.status = "waiting_for_verification"
        self._verification_event = asyncio.Event()
        self.verification_codes = {}
        logger.info(f"{self.exchange_name}: waiting for verification codes (timeout={timeout}s)")
        try:
            await asyncio.wait_for(self._verification_event.wait(), timeout=timeout)
            logger.info(f"{self.exchange_name}: verification codes received")
            return True
        except asyncio.TimeoutError:
            logger.warning(f"{self.exchange_name}: verification codes timed out after {timeout}s")
            return False
        finally:
            self._verification_event = None

    def submit_verification_codes(self, email_code: str, sms_code: str) -> None:
        """Called by the submit-verification endpoint."""
        self.verification_codes = {"email_code": email_code, "sms_code": sms_code}
        if self._verification_event:
            self._verification_event.set()


# Global registry of sessions
_sessions: Dict[str, ExchangeSession] = {}


def get_session(exchange_name: str) -> ExchangeSession:
    """Get or create an ExchangeSession for the given exchange."""
    if exchange_name not in _sessions:
        _sessions[exchange_name] = ExchangeSession(exchange_name)
    return _sessions[exchange_name]


def get_all_sessions() -> Dict[str, ExchangeSession]:
    return _sessions
