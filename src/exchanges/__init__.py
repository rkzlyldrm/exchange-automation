"""
Exchange automation factory.
"""
from src.exchanges.base import BaseExchangeAutomation
from src.exchanges.okx_tr import OKXTRAutomation
from src.exchanges.paribu import ParibuAutomation
from src.exchanges.cointr import CoinTRAutomation
from src.exchanges.binance_tr import BinanceTRAutomation
from src.exchanges.btcturk import BTCTurkAutomation
from src.exchanges.whitebit_tr import WhiteBitTRAutomation

# Registry: exchange_name → automation class
EXCHANGE_REGISTRY = {
    "okx_tr": OKXTRAutomation,
    "paribu": ParibuAutomation,
    "cointr": CoinTRAutomation,
    "binance_tr": BinanceTRAutomation,
    "btcturk": BTCTurkAutomation,
    "whitebit_tr": WhiteBitTRAutomation,
}


def get_exchange_automation(exchange_name: str) -> BaseExchangeAutomation:
    """Instantiate the automation class for the given exchange."""
    cls = EXCHANGE_REGISTRY.get(exchange_name)
    if cls is None:
        raise ValueError(f"No automation implemented for '{exchange_name}'")
    return cls()
