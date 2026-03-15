"""
TOTP code generation for exchange 2FA.
"""
import pyotp


def generate_totp_code(secret: str) -> str:
    """Generate current 6-digit TOTP code from base32 secret."""
    totp = pyotp.TOTP(secret)
    return totp.now()


def get_totp_remaining_seconds(secret: str) -> int:
    """Seconds remaining before the current TOTP code expires."""
    totp = pyotp.TOTP(secret)
    return totp.interval - (pyotp.utils.now() % totp.interval)
