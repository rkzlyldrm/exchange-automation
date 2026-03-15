"""
Abstract base class every exchange automation must implement.
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional

from src.browser.session import ExchangeSession


class BaseExchangeAutomation(ABC):
    """Interface for browser-based exchange operations."""

    exchange_name: str = ""

    @abstractmethod
    async def login(self, session: ExchangeSession, credentials: Dict[str, str]) -> dict:
        """
        Log into the exchange via browser.

        Args:
            session: The ExchangeSession wrapping the BrowserContext.
            credentials: Decrypted credentials (email, password, totp_secret, etc.)

        Returns:
            {"success": bool, "message": str}
        """

    @abstractmethod
    async def check_session(self, session: ExchangeSession) -> bool:
        """Return True if the browser session is still authenticated."""

    @abstractmethod
    async def withdraw_try(
        self,
        session: ExchangeSession,
        amount: float,
        iban: str,
        payment_account_id: str,
    ) -> dict:
        """
        Execute a TRY withdrawal.

        Returns:
            {"success": bool, "order_id": str|None, "message": str}
        """

    async def withdraw_crypto(
        self,
        session: ExchangeSession,
        asset: str,
        network: str,
        amount: float,
        address: str,
        phishing_code: str = "",
        receiver_platform: str = "",
    ) -> dict:
        """
        Execute a crypto withdrawal via browser automation (optional per exchange).

        Returns:
            {"success": bool, "message": str, "tx_id": str|None}
        """
        return {"success": False, "message": "Crypto withdrawal not implemented for this exchange", "tx_id": None}

    async def confirm_deposit(
        self,
        session: ExchangeSession,
        platform_name: str,
        amount: Optional[float] = None,
    ) -> dict:
        """
        Confirm a deposit via travel rule form (optional per exchange).

        Returns:
            {"success": bool, "message": str}
        """
        return {"success": False, "message": "Not implemented for this exchange"}

    async def keepalive(self, session: ExchangeSession) -> None:
        """Optional page-level keepalive. Override per exchange."""
        pass

    async def get_status(self, session: ExchangeSession) -> dict:
        """Return exchange-specific session health."""
        return session.get_status()
