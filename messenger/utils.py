"""
SecureStego Messenger — Utilities
Helper functions for file validation, security logging, and misc operations.
"""
import os
import random
import string
from django.conf import settings
from django.core.files.uploadedfile import InMemoryUploadedFile


# ── File Validation ─────────────────────────────────────────────────────────────

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'bmp', 'tiff', 'tif'}
MAX_FILE_SIZE_MB = 10


def validate_image_upload(file: InMemoryUploadedFile) -> tuple[bool, str]:
    """
    Validate an uploaded image file.
    Returns (is_valid: bool, error_message: str).
    """
    if file is None:
        return False, "No file provided."

    # Check file size
    if file.size > MAX_FILE_SIZE_MB * 1024 * 1024:
        return False, f"File too large. Maximum allowed size is {MAX_FILE_SIZE_MB} MB."

    # Check extension
    ext = file.name.rsplit('.', 1)[-1].lower() if '.' in file.name else ''
    if ext not in ALLOWED_EXTENSIONS:
        return False, (
            f"Invalid file type '.{ext}'. "
            f"Allowed types: {', '.join(sorted(ALLOWED_EXTENSIONS))}."
        )

    # Check MIME type via content_type header (basic check)
    allowed_mimes = {
        'image/png', 'image/jpeg', 'image/bmp',
        'image/tiff', 'image/x-tiff',
    }
    if file.content_type and file.content_type not in allowed_mimes:
        return False, "File content type not permitted."

    return True, ""


# ── Operation Name Generator ────────────────────────────────────────────────────

_ADJECTIVES = [
    'Crimson', 'Silent', 'Void', 'Shadow', 'Phantom', 'Cipher',
    'Ghost', 'Stealth', 'Neon', 'Obsidian', 'Quantum', 'Spectral',
    'Hollow', 'Frozen', 'Apex', 'Echo',
]
_NOUNS = [
    'Scythe', 'Walker', 'Whisper', 'Vector', 'Protocol', 'Node',
    'Signal', 'Layer', 'Stream', 'Pulse', 'Nexus', 'Veil',
    'Matrix', 'Cipher', 'Shard', 'Prism',
]


def generate_operation_name() -> str:
    """Generate a random operation codename like 'Op: Crimson_Scythe'."""
    adj = random.choice(_ADJECTIVES)
    noun = random.choice(_NOUNS)
    return f"Op: {adj}_{noun}"


# ── IP Address Helper ───────────────────────────────────────────────────────────

def get_client_ip(request) -> str:
    """Extract the real client IP from Django request, handling proxies."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', '0.0.0.0')


# ── Security Log Helper ─────────────────────────────────────────────────────────

def log_security_event(user, event_type: str, description: str = '', request=None):
    """Create a SecurityLog entry. Imported lazily to avoid circular imports."""
    from messenger.models import SecurityLog
    ip = get_client_ip(request) if request else None
    SecurityLog.objects.create(
        user=user,
        event_type=event_type,
        description=description,
        ip_address=ip,
    )


# ── Profile Auto-Create ─────────────────────────────────────────────────────────

def ensure_user_profile(user):
    """Get or create UserProfile for a user. Call after login/signup."""
    from messenger.models import UserProfile
    profile, _ = UserProfile.objects.get_or_create(user=user)
    return profile
