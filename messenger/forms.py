"""
SecureStego Messenger — Forms
All user-facing forms with validation.
"""
from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User
from messenger.encryption import is_valid_fernet_key


# ── Authentication Forms ────────────────────────────────────────────────────────

class SignupForm(UserCreationForm):
    """Registration form with email field."""
    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={
            'class': 'form-control stego-input',
            'placeholder': 'operator@domain.com',
            'autocomplete': 'email',
        })
    )

    class Meta:
        model = User
        fields = ('username', 'email', 'password1', 'password2')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['username'].widget.attrs.update({
            'class': 'form-control stego-input',
            'placeholder': 'Operator_ID',
            'autocomplete': 'username',
        })
        self.fields['password1'].widget.attrs.update({
            'class': 'form-control stego-input',
            'placeholder': '••••••••',
            'autocomplete': 'new-password',
        })
        self.fields['password2'].widget.attrs.update({
            'class': 'form-control stego-input',
            'placeholder': '••••••••',
            'autocomplete': 'new-password',
        })

    def clean_email(self):
        email = self.cleaned_data.get('email', '').strip().lower()
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError("An account with this email already exists.")
        return email

    def save(self, commit=True):
        user = super().save(commit=False)
        user.email = self.cleaned_data['email']
        if commit:
            user.save()
        return user


class LoginForm(AuthenticationForm):
    """Custom login form with styled inputs."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['username'].widget.attrs.update({
            'class': 'form-control stego-input',
            'placeholder': 'Operator_ID',
            'autocomplete': 'username',
        })
        self.fields['password'].widget.attrs.update({
            'class': 'form-control stego-input',
            'placeholder': '••••••••',
            'autocomplete': 'current-password',
        })


# ── Encryption Form ─────────────────────────────────────────────────────────────

class EncryptForm(forms.Form):
    """Step 1: user inputs the secret message to encrypt."""
    message = forms.CharField(
        min_length=1,
        max_length=10000,
        widget=forms.Textarea(attrs={
            'class': 'form-control stego-input stego-textarea',
            'placeholder': 'Enter message to be encrypted...',
            'rows': 6,
            'id': 'id_message',
            'spellcheck': 'false',
            'autocomplete': 'off',
        })
    )

    def clean_message(self):
        msg = self.cleaned_data.get('message', '').strip()
        if not msg:
            raise forms.ValidationError("Message cannot be empty.")
        return msg


# ── Steganography (Embed) Form ──────────────────────────────────────────────────

class EmbedForm(forms.Form):
    """Step 2: user provides a carrier image to hide the encrypted payload."""
    carrier_image = forms.ImageField(
        widget=forms.FileInput(attrs={
            'class': 'form-control stego-file-input',
            'accept': 'image/png,image/jpeg,image/bmp,image/tiff',
            'id': 'id_carrier_image',
        })
    )
    encrypted_payload = forms.CharField(
        widget=forms.HiddenInput(),
        required=True,
    )
    secret_key = forms.CharField(
        widget=forms.HiddenInput(),
        required=True,
    )

    def clean_carrier_image(self):
        img = self.cleaned_data.get('carrier_image')
        if img:
            # Max 10 MB
            if img.size > 10 * 1024 * 1024:
                raise forms.ValidationError("Image must be under 10 MB.")
            ext = img.name.rsplit('.', 1)[-1].lower()
            if ext not in ('png', 'jpg', 'jpeg', 'bmp', 'tiff', 'tif'):
                raise forms.ValidationError("Unsupported image format.")
        return img


# ── Extraction Form ─────────────────────────────────────────────────────────────

class ExtractForm(forms.Form):
    """User uploads a stego image to extract the hidden payload."""
    stego_image = forms.ImageField(
        widget=forms.FileInput(attrs={
            'class': 'form-control stego-file-input',
            'accept': 'image/png,image/jpeg,image/bmp,image/tiff',
            'id': 'id_stego_image',
        })
    )

    def clean_stego_image(self):
        img = self.cleaned_data.get('stego_image')
        if img:
            if img.size > 10 * 1024 * 1024:
                raise forms.ValidationError("Image must be under 10 MB.")
        return img


# ── Decryption Form ─────────────────────────────────────────────────────────────

class DecryptForm(forms.Form):
    """User provides the encrypted payload and secret key to decrypt."""
    encrypted_payload = forms.CharField(
        widget=forms.Textarea(attrs={
            'class': 'form-control stego-input stego-textarea',
            'placeholder': 'Paste extracted cipher payload here...',
            'rows': 4,
            'spellcheck': 'false',
        })
    )
    secret_key = forms.CharField(
        min_length=10,
        widget=forms.TextInput(attrs={
            'class': 'form-control stego-input',
            'placeholder': 'Enter your Fernet secret key...',
            'autocomplete': 'off',
            'spellcheck': 'false',
        })
    )

    def clean_secret_key(self):
        key = self.cleaned_data.get('secret_key', '').strip()
        if not is_valid_fernet_key(key):
            raise forms.ValidationError(
                "Invalid key format. Key must be a valid 32-byte base64 Fernet key."
            )
        return key
