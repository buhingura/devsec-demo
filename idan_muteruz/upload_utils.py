"""
Upload path helpers for user-submitted files.

These functions are passed as the ``upload_to`` argument to Django FileField /
ImageField.  Using a UUID-derived path instead of the original filename
provides three security properties:

1. Path traversal prevention
   The caller-supplied filename is never used as-is.  Sequences like
   ``../../etc/passwd`` or ``../manage.py`` cannot escape MEDIA_ROOT because
   the generated path contains only a UUID and the (sanitised) extension.

2. Filename guessing prevention
   Avatars and documents are served only through access-controlled views, not
   via MEDIA_URL.  Even so, unpredictable storage names make it harder for an
   attacker to enumerate or guess another user's file URL if a URL ever leaked
   (e.g. from a log file or referrer header).

3. Collision avoidance
   Two uploads of the same original file get different storage paths, so a
   later upload never silently overwrites an earlier one.

Directory structure
-------------------
    MEDIA_ROOT/
        avatars/<user_pk>/<uuid>.<ext>
        documents/<user_pk>/<uuid>.<ext>

Organising by user primary key keeps related files together and simplifies
bulk-deletion if an account is deleted, without leaking the original filename.
"""
import os
import uuid


def avatar_upload_path(instance, filename: str) -> str:
    """
    Return a safe storage path for a profile avatar.

    ``instance`` is the unsaved ``Profile`` model instance.
    ``filename`` is the original name supplied by the client — it is used
    only to extract the file extension; the rest is discarded.
    """
    ext = os.path.splitext(filename)[1].lower()
    return f'avatars/{instance.user_id}/{uuid.uuid4()}{ext}'


def document_upload_path(instance, filename: str) -> str:
    """
    Return a safe storage path for a private user document.

    ``instance`` is the unsaved ``UserDocument`` model instance.
    ``filename`` is the original name supplied by the client — used only for
    the extension.
    """
    ext = os.path.splitext(filename)[1].lower()
    return f'documents/{instance.owner_id}/{uuid.uuid4()}{ext}'
