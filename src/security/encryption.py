"""
Fernet encryption utilities — mirrors main app's security.py
"""
import base64
import hashlib

from cryptography.fernet import Fernet

from src.config import settings


def get_fernet() -> Fernet:
    """Get Fernet cipher instance (same key derivation as main app)."""
    key = settings.ENCRYPTION_KEY
    if isinstance(key, str):
        key = key.encode()

    # Ensure key is 32 bytes for Fernet (same as main app)
    if len(key) != 44:  # Base64 encoded 32 bytes = 44 chars
        key = base64.urlsafe_b64encode(hashlib.sha256(key).digest())

    return Fernet(key)


def encrypt_data(data: str) -> str:
    """Encrypt sensitive data using Fernet."""
    if not data:
        return ""
    fernet = get_fernet()
    encrypted = fernet.encrypt(data.encode())
    return encrypted.decode()


def decrypt_data(encrypted_data: str) -> str:
    """Decrypt data encrypted with Fernet."""
    if not encrypted_data:
        return ""
    fernet = get_fernet()
    decrypted = fernet.decrypt(encrypted_data.encode())
    return decrypted.decode()


def encrypt_file_content(data: str) -> bytes:
    """Encrypt a string for writing to a file (returns raw bytes)."""
    fernet = get_fernet()
    return fernet.encrypt(data.encode())


def decrypt_file_content(encrypted_data: bytes) -> str:
    """Decrypt bytes read from an encrypted file."""
    fernet = get_fernet()
    return fernet.decrypt(encrypted_data).decode()
