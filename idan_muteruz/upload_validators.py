"""
Upload validators for user-submitted files.

Two validators are exported:
    validate_avatar(file)   — images for user profile pictures
    validate_document(file) — PDF documents for private storage

Security model
--------------
Every upload passes THREE independent checks before being accepted:

1. Size limit
   Enforced first (cheapest check).  Rejects oversized files before any
   content is read, limiting memory and disk exposure.

2. File extension whitelist
   Quick coarse filter.  A necessary-but-not-sufficient check: an attacker
   can rename any file, so the extension alone is NOT trusted to determine
   type.  It merely provides a fast path for obviously wrong submissions.

3. Content inspection
   The authoritative type check.  Does not trust the client-supplied
   Content-Type header.

   · Images — Pillow opens and calls verify().  An executable or script
     disguised as an image fails here because Pillow cannot decode it as a
     valid image format.

   · PDFs — the first four bytes are compared against the PDF magic
     signature (b'%PDF').  A renamed EXE, script, or ZIP fails because
     its magic bytes differ.

What is deliberately NOT done
------------------------------
· Anti-virus scanning — out of scope for application-layer validation;
  this belongs at the infrastructure layer.
· Archive extraction — no ZIP/TAR handling; such files are rejected.
· HTML/SVG — not in the allowed sets; both can execute scripts.
· SSRF via SVG — impossible because SVG is rejected at the extension step.

File pointer state
------------------
All validators leave the file pointer at position 0 after returning so
Django's storage backend can read the file from the beginning.
"""
import os

from django import forms
from django.conf import settings

# ---------------------------------------------------------------------------
# Configurable limits (can be overridden in settings.py)
# ---------------------------------------------------------------------------

_DEFAULT_AVATAR_MAX   = 2 * 1024 * 1024   # 2 MB
_DEFAULT_DOCUMENT_MAX = 5 * 1024 * 1024   # 5 MB


def _avatar_max() -> int:
    return getattr(settings, 'AVATAR_MAX_UPLOAD_BYTES', _DEFAULT_AVATAR_MAX)


def _document_max() -> int:
    return getattr(settings, 'DOCUMENT_MAX_UPLOAD_BYTES', _DEFAULT_DOCUMENT_MAX)


# ---------------------------------------------------------------------------
# Allowed types
# ---------------------------------------------------------------------------

_AVATAR_EXTENSIONS   = {'.jpg', '.jpeg', '.png', '.webp', '.gif'}
_DOCUMENT_EXTENSIONS = {'.pdf'}

# PDF magic signature — first 4 bytes of every valid PDF file.
_PDF_MAGIC = b'%PDF'


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _enforce_size(file, max_bytes: int, label: str) -> None:
    """Raise ValidationError if *file* exceeds *max_bytes*."""
    file.seek(0, 2)          # seek to end to find size
    size = file.tell()
    file.seek(0)             # reset for subsequent reads
    if size > max_bytes:
        limit_mb = max_bytes / (1024 * 1024)
        actual_mb = size / (1024 * 1024)
        raise forms.ValidationError(
            f'{label} must not exceed {limit_mb:.0f} MB '
            f'(uploaded file is {actual_mb:.1f} MB).'
        )


def _enforce_extension(filename: str, allowed: set, label: str) -> str:
    """Return the lowercase extension or raise ValidationError."""
    ext = os.path.splitext(filename)[1].lower()
    if ext not in allowed:
        friendly = ', '.join(sorted(allowed))
        raise forms.ValidationError(
            f'{label}: unsupported file type. '
            f'Allowed extensions: {friendly}.'
        )
    return ext


# ---------------------------------------------------------------------------
# Public validators
# ---------------------------------------------------------------------------

def validate_avatar(file) -> None:
    """
    Validate a profile-picture upload.

    Accepts: JPEG, PNG, WebP, GIF up to 2 MB (configurable via
    AVATAR_MAX_UPLOAD_BYTES).

    Raises django.forms.ValidationError on any check failure.
    File pointer is reset to 0 before returning.
    """
    # Pillow import is deferred so the validator module can be imported
    # safely even in environments without Pillow (tests that mock it).
    try:
        from PIL import Image, UnidentifiedImageError
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            'Pillow is required for image validation. '
            'Install it with: pip install Pillow'
        ) from exc

    # 1. Size
    _enforce_size(file, _avatar_max(), 'Avatar')

    # 2. Extension
    _enforce_extension(
        getattr(file, 'name', ''),
        _AVATAR_EXTENSIONS,
        'Avatar',
    )

    # 3. Content — Pillow verify
    #    Image.open() is lazy; .verify() forces full validation and raises
    #    if the bytes do not form a valid image.
    #    After verify() the image object is exhausted — we must reopen to
    #    use the file further, but we only need the pointer reset here.
    try:
        file.seek(0)
        img = Image.open(file)
        img.verify()
    except Exception as exc:
        # UnidentifiedImageError, OSError, and any format-specific error
        # are all collapsed into a single user-facing message to avoid
        # leaking implementation details.
        raise forms.ValidationError(
            'The uploaded file is not a valid image.'
        ) from exc
    finally:
        file.seek(0)


def validate_document(file) -> None:
    """
    Validate a private document upload.

    Accepts: PDF up to 5 MB (configurable via DOCUMENT_MAX_UPLOAD_BYTES).

    The magic-byte check means that a file renamed to ``.pdf`` but
    containing EXE, PHP, or any non-PDF content is rejected.

    Raises django.forms.ValidationError on any check failure.
    File pointer is reset to 0 before returning.
    """
    # 1. Size
    _enforce_size(file, _document_max(), 'Document')

    # 2. Extension
    _enforce_extension(
        getattr(file, 'name', ''),
        _DOCUMENT_EXTENSIONS,
        'Document',
    )

    # 3. Magic bytes — %PDF
    try:
        file.seek(0)
        header = file.read(len(_PDF_MAGIC))
    finally:
        file.seek(0)

    if header != _PDF_MAGIC:
        raise forms.ValidationError(
            'The uploaded file does not appear to be a valid PDF.'
        )
