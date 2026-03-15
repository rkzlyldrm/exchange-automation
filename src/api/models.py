"""
Pydantic request / response schemas for the automation service API.
"""
from typing import Optional, Dict, Any, List
from pydantic import BaseModel


# ── Requests ───────────────────────────────────────────────

class WithdrawTRYRequest(BaseModel):
    exchange_name: str
    amount: float
    iban: str
    payment_account_id: str


class WithdrawCryptoRequest(BaseModel):
    exchange_name: str
    asset: str                      # "USDT"
    network: str                    # "TRON", "AVAXC"
    amount: float
    address: str                    # Destination wallet address
    phishing_code: str = ""         # User's BTCTurk phishing code for email verification
    receiver_platform: str = ""     # Receiver exchange key (e.g. "okx_tr", "binance_global")


class ConfirmDepositRequest(BaseModel):
    platform_name: str
    amount: Optional[float] = None


class TravelRuleConfirmRequest(BaseModel):
    travel_rule_id: str
    source_exchange: str


# ── Responses ──────────────────────────────────────────────

class SessionStatus(BaseModel):
    exchange_name: str
    status: str
    is_logged_in: bool
    last_login_at: Optional[float] = None
    last_error: Optional[str] = None
    has_token: bool = False
    current_url: Optional[str] = None


class WithdrawTRYResponse(BaseModel):
    success: bool
    order_id: Optional[str] = None
    message: str


class WithdrawCryptoResponse(BaseModel):
    success: bool
    message: str
    tx_id: Optional[str] = None


class LoginResponse(BaseModel):
    success: bool
    message: str


class HealthResponse(BaseModel):
    status: str
    browser: Dict[str, Any]
    sessions: List[SessionStatus]
