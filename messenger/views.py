"""
SecureStego Messenger — Views
All views are function-based for clarity and Django convention compliance.
"""
import io
import os
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib import messages
from django.http import HttpResponse, JsonResponse
from django.views.decorators.http import require_POST
from django.utils import timezone
from django.core.files.base import ContentFile

from messenger.forms import (
    SignupForm, LoginForm, EncryptForm, EmbedForm, ExtractForm, DecryptForm
)
from messenger.models import StegOperation, SecurityLog, UserProfile
from messenger.encryption import (
    fernet_encrypt, fernet_decrypt,
    generate_fernet_key, is_valid_fernet_key
)
from messenger.steganography import embed_message, extract_message, get_image_capacity_info
from messenger.utils import (
    validate_image_upload, generate_operation_name,
    log_security_event, ensure_user_profile, get_client_ip
)


# ── Landing Page ────────────────────────────────────────────────────────────────

def home(request):
    """Public landing page. Redirect authenticated users to dashboard."""
    if request.user.is_authenticated:
        return redirect('dashboard')
    return render(request, 'messenger/home.html')


# ── Authentication ──────────────────────────────────────────────────────────────

def signup_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')

    if request.method == 'POST':
        form = SignupForm(request.POST)
        if form.is_valid():
            user = form.save()
            ensure_user_profile(user)
            login(request, user)
            log_security_event(user, 'login', 'Account created and logged in.', request)
            messages.success(request, f"Welcome, {user.username}. Node activated.")
            return redirect('dashboard')
    else:
        form = SignupForm()

    return render(request, 'messenger/signup.html', {'form': form})


def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')

    if request.method == 'POST':
        form = LoginForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            ensure_user_profile(user)
            log_security_event(user, 'login', 'Login successful.', request)
            return redirect('dashboard')
        else:
            log_security_event(
                User.objects.filter(username=request.POST.get('username')).first()
                or User(username='unknown'),
                'login',
                f"Failed login attempt for: {request.POST.get('username', '')}",
                request,
            )
    else:
        form = LoginForm()

    return render(request, 'messenger/login.html', {'form': form})


@login_required
def logout_view(request):
    log_security_event(request.user, 'logout', 'User logged out.', request)
    logout(request)
    return redirect('login')


# ── Dashboard ───────────────────────────────────────────────────────────────────

@login_required
def dashboard(request):
    profile = ensure_user_profile(request.user)
    recent_ops = StegOperation.objects.filter(user=request.user)[:5]
    total_ops = StegOperation.objects.filter(user=request.user).count()
    encode_count = StegOperation.objects.filter(user=request.user, operation_type='encode').count()
    decode_count = StegOperation.objects.filter(user=request.user, operation_type='decode').count()

    context = {
        'profile': profile,
        'recent_ops': recent_ops,
        'total_ops': total_ops,
        'encode_count': encode_count,
        'decode_count': decode_count,
    }
    return render(request, 'messenger/dashboard.html', context)


# ── Encrypt & Embed (4-step flow) ───────────────────────────────────────────────

@login_required
def encrypt_view(request):
    """
    Step 1: User types message.
    Step 2: System encrypts it, shows the key, moves to embed step.
    """
    profile = ensure_user_profile(request.user)
    form = EncryptForm()
    encrypted_result = None
    secret_key = None

    if request.method == 'POST':
        form = EncryptForm(request.POST)
        if form.is_valid():
            plaintext = form.cleaned_data['message']
            secret_key = generate_fernet_key()
            try:
                encrypted_result = fernet_encrypt(plaintext, secret_key)
                log_security_event(request.user, 'encode', f"Message encrypted ({len(plaintext)} chars).", request)
                messages.success(request, "Message encrypted successfully. Save your key securely before proceeding.")
            except ValueError as e:
                messages.error(request, str(e))

    context = {
        'form': form,
        'encrypted_result': encrypted_result,
        'secret_key': secret_key,
        'profile': profile,
    }
    return render(request, 'messenger/encrypt.html', context)


@login_required
def embed_view(request):
    """
    Step 3: User uploads a carrier image.
    The encrypted payload is embedded → stego image generated → downloadable.
    """
    profile = ensure_user_profile(request.user)
    form = EmbedForm()
    stego_op = None

    if request.method == 'POST':
        form = EmbedForm(request.POST, request.FILES)
        if form.is_valid():
            carrier_file = form.cleaned_data['carrier_image']
            encrypted_payload = form.cleaned_data['encrypted_payload']
            secret_key = form.cleaned_data['secret_key']

            # Validate image
            is_valid, err = validate_image_upload(carrier_file)
            if not is_valid:
                messages.error(request, err)
            else:
                try:
                    source_bytes = carrier_file.read()
                    stego_bytes = embed_message(source_bytes, encrypted_payload)

                    # Save operation record
                    op = StegOperation(
                        user=request.user,
                        operation_type='encode',
                        operation_name=generate_operation_name(),
                        status='verified',
                        encrypted_payload=encrypted_payload,
                        encryption_method='Fernet',
                        message_length=len(encrypted_payload),
                    )
                    # Save source image
                    carrier_file.seek(0)
                    op.source_image.save(f"src_{op.short_id}.png", ContentFile(source_bytes), save=False)
                    op.stego_image.save(f"stego_{op.short_id}.png", ContentFile(stego_bytes), save=False)
                    op.save()
                    stego_op = op

                    log_security_event(request.user, 'encode', f"Stego image generated: {op.operation_name}", request)
                    messages.success(request, f"Stego image created: {op.operation_name}")

                except ValueError as e:
                    messages.error(request, str(e))
        else:
            messages.error(request, "Please correct the form errors.")

    context = {
        'form': form,
        'stego_op': stego_op,
        'profile': profile,
    }
    return render(request, 'messenger/embed.html', context)


@login_required
def download_stego(request, op_id):
    """Serve the stego image as a file download."""
    op = get_object_or_404(StegOperation, id=op_id, user=request.user)
    if not op.stego_image:
        messages.error(request, "No stego image found for this operation.")
        return redirect('dashboard')

    with op.stego_image.open('rb') as f:
        response = HttpResponse(f.read(), content_type='image/png')
        response['Content-Disposition'] = f'attachment; filename="{op.operation_name.replace(": ", "_").replace(" ", "_")}.png"'
        return response


# ── Extract & Decrypt ───────────────────────────────────────────────────────────

@login_required
def extract_view(request):
    """
    Receiver uploads a stego image → system extracts the hidden payload.
    """
    profile = ensure_user_profile(request.user)
    form = ExtractForm()
    extracted_payload = None

    if request.method == 'POST':
        form = ExtractForm(request.POST, request.FILES)
        if form.is_valid():
            stego_file = form.cleaned_data['stego_image']

            is_valid, err = validate_image_upload(stego_file)
            if not is_valid:
                messages.error(request, err)
            else:
                try:
                    stego_bytes = stego_file.read()
                    extracted_payload = extract_message(stego_bytes)

                    # Log the extraction
                    op = StegOperation.objects.create(
                        user=request.user,
                        operation_type='decode',
                        operation_name=generate_operation_name(),
                        status='extracted',
                        encrypted_payload=extracted_payload,
                        encryption_method='Fernet',
                    )
                    log_security_event(request.user, 'decode', f"Payload extracted: {op.operation_name}", request)
                    messages.success(request, "Hidden payload extracted. Proceed to decryption.")

                except ValueError as e:
                    messages.error(request, str(e))
                    log_security_event(request.user, 'failed_decrypt', str(e), request)

    context = {
        'form': form,
        'extracted_payload': extracted_payload,
        'profile': profile,
    }
    return render(request, 'messenger/extract.html', context)


@login_required
def decrypt_view(request):
    """
    Receiver enters the ciphertext + secret key → recovers the original message.
    """
    profile = ensure_user_profile(request.user)
    form = DecryptForm(request.POST or None)
    decrypted_message = None

    if request.method == 'POST' and form.is_valid():
        encrypted_payload = form.cleaned_data['encrypted_payload']
        secret_key = form.cleaned_data['secret_key']
        try:
            decrypted_message = fernet_decrypt(encrypted_payload, secret_key)
            log_security_event(request.user, 'decode', "Message decrypted successfully.", request)
            messages.success(request, "Message decrypted successfully.")
        except ValueError as e:
            messages.error(request, str(e))
            log_security_event(request.user, 'failed_decrypt', str(e), request)

    context = {
        'form': form,
        'decrypted_message': decrypted_message,
        'profile': profile,
    }
    return render(request, 'messenger/decrypt.html', context)


# ── History ─────────────────────────────────────────────────────────────────────

@login_required
def history_view(request):
    """Display all past operations for the current user."""
    profile = ensure_user_profile(request.user)
    operations = StegOperation.objects.filter(user=request.user)
    context = {
        'operations': operations,
        'profile': profile,
    }
    return render(request, 'messenger/history.html', context)


# ── Settings / Key Management ───────────────────────────────────────────────────

@login_required
def settings_view(request):
    """Key management and security settings page."""
    profile = ensure_user_profile(request.user)
    new_key = None

    if request.method == 'POST':
        action = request.POST.get('action')
        if action == 'generate_key':
            new_key = generate_fernet_key()
            log_security_event(request.user, 'key_generated', "New Fernet key generated.", request)
            messages.success(request, "New AES-256 key generated. Copy it now — it will not be stored.")
        elif action == 'toggle_2fa':
            profile.two_factor_enabled = not profile.two_factor_enabled
            profile.save()
        elif action == 'toggle_session_timeout':
            profile.session_timeout = not profile.session_timeout
            profile.save()

    # Key history (last 10 key-generated events)
    key_events = SecurityLog.objects.filter(
        user=request.user, event_type='key_generated'
    )[:10]

    context = {
        'profile': profile,
        'new_key': new_key,
        'key_events': key_events,
    }
    return render(request, 'messenger/settings.html', context)


# ── Security Log ────────────────────────────────────────────────────────────────

@login_required
def security_log_view(request):
    """Full security audit log for the user."""
    profile = ensure_user_profile(request.user)
    logs = SecurityLog.objects.filter(user=request.user)[:100]
    context = {
        'logs': logs,
        'profile': profile,
    }
    return render(request, 'messenger/security_log.html', context)


# ── AJAX: Key Validation ─────────────────────────────────────────────────────────

def validate_key_ajax(request):
    """Quick AJAX endpoint to validate a Fernet key format in real-time."""
    if request.method == 'GET':
        key = request.GET.get('key', '')
        return JsonResponse({'valid': is_valid_fernet_key(key)})
    return JsonResponse({'valid': False})
