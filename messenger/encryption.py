"""
SecureStego Messenger — Encryption Engine
Provides Fernet-based symmetric encryption with optional AES-GCM mode.
All keys are URL-safe base64 encoded strings.
"""
import os
import base64
import secrets
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# ── Key Generation ─────────────────────────────────────────────────────────────

def generate_fernet_key() -> str:
    """Generate a new Fernet key and return it as a URL-safe base64 string."""
    key = Fernet.generate_key()
    return key.decode('utf-8')


def generate_aes_key(bits: int = 256) -> str:
    """Generate a random AES key of given bit length, returned as hex string."""
    key_bytes = bits // 8
    return secrets.token_hex(key_bytes)


def derive_key_from_password(password: str, salt: bytes = None) -> tuple[bytes, bytes]:
    """
    Derive a 32-byte Fernet-compatible key from a human password using PBKDF2.
    Returns (key_bytes, salt_bytes).
    """
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480_000,
    )
    key_bytes = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key_bytes, salt


# ── Fernet Encryption (primary) ────────────────────────────────────────────────

def fernet_encrypt(plaintext: str, key: str) -> str:
    """
    Encrypt a plaintext string using a Fernet key.
    Returns the ciphertext as a UTF-8 string.
    Raises ValueError on invalid key format.
    """
    try:
        f = Fernet(key.encode('utf-8') if isinstance(key, str) else key)
        token = f.encrypt(plaintext.encode('utf-8'))
        return token.decode('utf-8')
    except Exception as e:
        raise ValueError(f"Encryption failed: {e}") from e


def fernet_decrypt(ciphertext: str, key: str) -> str:
    """
    Decrypt a Fernet ciphertext string.
    Returns the original plaintext.
    Raises ValueError if key is wrong or token is invalid/tampered.
    """
    try:
        f = Fernet(key.encode('utf-8') if isinstance(key, str) else key)
        plaintext = f.decrypt(ciphertext.encode('utf-8') if isinstance(ciphertext, str) else ciphertext)
        return plaintext.decode('utf-8')
    except InvalidToken:
        raise ValueError("Decryption failed: invalid key or corrupted data.")
    except Exception as e:
        raise ValueError(f"Decryption failed: {e}") from e


# ── AES-GCM Encryption (optional advanced mode) ────────────────────────────────

def aes_gcm_encrypt(plaintext: str, hex_key: str) -> dict:
    """
    Encrypt using AES-256-GCM.
    Returns a dict with 'ciphertext', 'nonce', all hex-encoded.
    hex_key must be a 64-character hex string (32 bytes = 256 bits).
    """
    try:
        key_bytes = bytes.fromhex(hex_key)
        nonce = os.urandom(12)
        aesgcm = AESGCM(key_bytes)
        ct = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
        return {
            'ciphertext': ct.hex(),
            'nonce': nonce.hex(),
        }
    except Exception as e:
        raise ValueError(f"AES-GCM encryption failed: {e}") from e


def aes_gcm_decrypt(ciphertext_hex: str, nonce_hex: str, hex_key: str) -> str:
    """
    Decrypt AES-256-GCM ciphertext.
    Returns the original plaintext string.
    """
    try:
        key_bytes = bytes.fromhex(hex_key)
        nonce = bytes.fromhex(nonce_hex)
        ct = bytes.fromhex(ciphertext_hex)
        aesgcm = AESGCM(key_bytes)
        plaintext = aesgcm.decrypt(nonce, ct, None)
        return plaintext.decode('utf-8')
    except Exception as e:
        raise ValueError(f"AES-GCM decryption failed: {e}") from e


# ── Validation Helpers ─────────────────────────────────────────────────────────

def is_valid_fernet_key(key: str) -> bool:
    """Return True if the string is a structurally valid Fernet key."""
    try:
        decoded = base64.urlsafe_b64decode(key.encode())
        return len(decoded) == 32
    except Exception:
        return False


def is_valid_aes_key(hex_key: str, bits: int = 256) -> bool:
    """Return True if the hex string represents a valid AES key of given bit size."""
    try:
        return len(bytes.fromhex(hex_key)) == bits // 8
    except Exception:
        return False
