"""
SecureStego Messenger — Models
Defines UserProfile, StegOperation, and MessageLog.
"""
import uuid
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone


class UserProfile(models.Model):
    """Extended profile for each registered operator."""
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    operator_id = models.CharField(max_length=64, unique=True, blank=True)
    node_status = models.CharField(
        max_length=16,
        choices=[('secure', 'Secure'), ('warning', 'Warning'), ('offline', 'Offline')],
        default='secure',
    )
    two_factor_enabled = models.BooleanField(default=False)
    session_timeout = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Profile({self.user.username})"

    def save(self, *args, **kwargs):
        # Auto-generate operator_id from username if not set
        if not self.operator_id:
            self.operator_id = f"Operator_{self.user.username[:8].capitalize()}"
        super().save(*args, **kwargs)


def stego_image_upload_path(instance, filename):
    return f"stego_images/{instance.user.username}/{filename}"


def source_image_upload_path(instance, filename):
    return f"uploads/{instance.user.username}/{filename}"


class StegOperation(models.Model):
    """
    Records every encrypt+embed or extract+decrypt operation.
    Links the source image, the stego image, and the encrypted payload.
    """
    OPERATION_TYPES = [
        ('encode', 'Encode'),   # encrypt + embed
        ('decode', 'Decode'),   # extract + decrypt
    ]
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('verified', 'Verified'),
        ('extracted', 'Extracted'),
        ('failed', 'Failed'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='operations')
    operation_type = models.CharField(max_length=8, choices=OPERATION_TYPES)
    operation_name = models.CharField(max_length=128, blank=True)  # e.g. "Op: Crimson_Scythe"
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default='pending')

    # Images
    source_image = models.ImageField(upload_to=source_image_upload_path, null=True, blank=True)
    stego_image = models.ImageField(upload_to=stego_image_upload_path, null=True, blank=True)

    # Encrypted payload (stored only temporarily — never the plaintext)
    encrypted_payload = models.TextField(blank=True)

    # Metadata
    encryption_method = models.CharField(max_length=32, default='Fernet')
    message_length = models.PositiveIntegerField(default=0)   # character count of original message
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.operation_name or self.id} [{self.operation_type}] by {self.user.username}"

    @property
    def short_id(self):
        return str(self.id)[:8].upper()


class SecurityLog(models.Model):
    """Audit log for security-relevant events."""
    EVENT_TYPES = [
        ('login', 'Login'),
        ('logout', 'Logout'),
        ('encode', 'Encode Operation'),
        ('decode', 'Decode Operation'),
        ('key_generated', 'Key Generated'),
        ('failed_decrypt', 'Failed Decryption'),
        ('invalid_upload', 'Invalid Upload'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='security_logs')
    event_type = models.CharField(max_length=24, choices=EVENT_TYPES)
    description = models.TextField(blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"[{self.event_type}] {self.user.username} at {self.timestamp}"
