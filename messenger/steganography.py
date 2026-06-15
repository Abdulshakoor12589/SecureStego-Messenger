"""
SecureStego Messenger — Steganography Engine
Implements LSB (Least Significant Bit) steganography using Pillow.
This technique hides data in the least significant bits of pixel RGB values,
causing zero perceptible visual distortion.
"""
from PIL import Image
import io
import math


# ── Constants ──────────────────────────────────────────────────────────────────
DELIMITER = "<<STEGO_END>>"      # marks end of hidden payload
BITS_PER_CHANNEL = 1             # bits hidden per colour channel (1 = minimal distortion)


# ── Capacity Check ─────────────────────────────────────────────────────────────

def max_payload_bytes(image: Image.Image) -> int:
    """
    Return the maximum number of bytes that can be hidden in this image.
    Formula: (width * height * 3 channels * bits_per_channel) / 8
    """
    w, h = image.size
    return (w * h * 3 * BITS_PER_CHANNEL) // 8


# ── Embedding ──────────────────────────────────────────────────────────────────

def embed_message(source_image_bytes: bytes, message: str) -> bytes:
    """
    Hide a UTF-8 message string inside an image using LSB steganography.

    Args:
        source_image_bytes: Raw bytes of the source image file.
        message: The plaintext or ciphertext string to hide.

    Returns:
        PNG bytes of the stego image.

    Raises:
        ValueError: If the message is too long for the image capacity.
    """
    img = Image.open(io.BytesIO(source_image_bytes)).convert('RGB')
    w, h = img.size
    pixels = list(img.getdata())

    # Append delimiter so extraction knows where the payload ends
    payload = message + DELIMITER
    payload_bits = _str_to_bits(payload)

    capacity = max_payload_bytes(img) * 8
    if len(payload_bits) > capacity:
        raise ValueError(
            f"Message too large: needs {len(payload_bits)} bits, "
            f"image capacity is {capacity} bits."
        )

    # Embed bits into LSBs of R, G, B channels sequentially
    bit_index = 0
    new_pixels = []

    for pixel in pixels:
        r, g, b = pixel
        channels = [r, g, b]
        new_channels = []

        for ch in channels:
            if bit_index < len(payload_bits):
                # Clear LSB then set it to our payload bit
                new_ch = (ch & ~1) | int(payload_bits[bit_index])
                bit_index += 1
            else:
                new_ch = ch
            new_channels.append(new_ch)

        new_pixels.append(tuple(new_channels))

    # Build the stego image
    stego_img = Image.new('RGB', (w, h))
    stego_img.putdata(new_pixels)

    # Always save as PNG to avoid lossy compression destroying the hidden data
    output = io.BytesIO()
    stego_img.save(output, format='PNG', optimize=False)
    return output.getvalue()


# ── Extraction ─────────────────────────────────────────────────────────────────

def extract_message(stego_image_bytes: bytes) -> str:
    """
    Extract a hidden message from a stego image.

    Args:
        stego_image_bytes: Raw bytes of the stego image.

    Returns:
        The hidden message string (ciphertext or plaintext).

    Raises:
        ValueError: If no valid payload is found.
    """
    img = Image.open(io.BytesIO(stego_image_bytes)).convert('RGB')
    pixels = list(img.getdata())

    bits = []
    for pixel in pixels:
        for ch in pixel:          # R, G, B
            bits.append(str(ch & 1))

    # Reconstruct characters from 8-bit chunks
    extracted = _bits_to_str(bits)

    if DELIMITER not in extracted:
        raise ValueError(
            "No hidden payload detected in this image. "
            "Ensure you uploaded the correct stego image."
        )

    return extracted.split(DELIMITER)[0]


# ── Internal Helpers ───────────────────────────────────────────────────────────

def _str_to_bits(text: str) -> list[str]:
    """Convert a UTF-8 string to a list of '0'/'1' bit characters."""
    bits = []
    for byte in text.encode('utf-8'):
        bits.extend(list(f'{byte:08b}'))
    return bits


def _bits_to_str(bits: list[str]) -> str:
    """
    Reconstruct a UTF-8 string from a list of '0'/'1' bit characters.
    Stops at the first byte that would cause a UTF-8 decode error to avoid
    processing the entire (potentially huge) image pixel array.
    """
    chars = []
    for i in range(0, len(bits) - 7, 8):
        byte_val = int(''.join(bits[i:i+8]), 2)
        try:
            char = bytes([byte_val]).decode('utf-8')
            chars.append(char)
            # Early exit once we find the full delimiter
            partial = ''.join(chars)
            if DELIMITER in partial:
                return partial
        except (UnicodeDecodeError, ValueError):
            # Multi-byte UTF-8 characters span multiple bytes; continue
            continue
    return ''.join(chars)


# ── Capacity Utility ───────────────────────────────────────────────────────────

def get_image_capacity_info(source_image_bytes: bytes) -> dict:
    """
    Return capacity metadata for an image — useful for UI feedback.
    """
    img = Image.open(io.BytesIO(source_image_bytes)).convert('RGB')
    w, h = img.size
    max_bytes = max_payload_bytes(img)
    return {
        'width': w,
        'height': h,
        'pixels': w * h,
        'max_bytes': max_bytes,
        'max_chars_approx': max_bytes // 4,   # conservative UTF-8 estimate
    }
