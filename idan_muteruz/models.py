from django.conf import settings
from django.db import models
from django.utils.translation import gettext_lazy as _

from .upload_utils import avatar_upload_path, document_upload_path


class LoginAttempt(models.Model):
    """
    Audit record for every login attempt — both failures and successes.

    Used by the brute-force protection layer to count recent failures per
    username and decide whether to enforce a temporary lockout.

    Design notes:
    · Lockout is account-scoped (per username), not IP-scoped.
      IP-based blocking causes collateral damage for users behind shared NAT
      and is trivially bypassed with a new IP.  Account-scoping is more
      precise: it penalises the targeted account, not the network.
    · ip_address is recorded for audit purposes only — it is not used in
      lockout decisions.
    · Records are immutable (no updates); old rows accumulate and can be
      pruned by a periodic task once they exceed the lockout window.
    · username is stored as-is but matched case-insensitively in queries,
      consistent with Django's own login behaviour.
    """

    username   = models.CharField(max_length=150, db_index=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    timestamp  = models.DateTimeField(auto_now_add=True, db_index=True)
    succeeded  = models.BooleanField(default=False)

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            # Supports the primary lockout query:
            # WHERE username=? AND succeeded=False AND timestamp >= ?
            models.Index(fields=['username', 'succeeded', 'timestamp']),
        ]

    def __str__(self) -> str:
        status = 'ok' if self.succeeded else 'fail'
        return f'{self.username} [{status}] @ {self.timestamp:%Y-%m-%d %H:%M:%S}'


class Profile(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='profile',
    )
    display_name = models.CharField(max_length=150, blank=True, help_text=_('Preferred display name'))
    bio = models.TextField(blank=True, help_text=_('Optional short biography'))
    avatar = models.ImageField(
        upload_to=avatar_upload_path,
        null=True,
        blank=True,
        help_text=_('Profile picture (JPEG, PNG, WebP, or GIF; max 2 MB)'),
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('profile')
        verbose_name_plural = _('profiles')
        permissions = [
            ('can_access_admin_panel', 'Can access the admin panel'),
        ]

    def __str__(self) -> str:
        return self.display_name or self.user.get_full_name() or self.user.username


class UserDocument(models.Model):
    """
    A private PDF document uploaded by a registered user.

    Security design:
    · Files are stored at a UUID-derived path so the original filename is
      never used on disk (path traversal prevention, guessing prevention).
    · The ``original_name`` field stores the user-supplied filename for
      display purposes only; it is never used to construct a file path.
    · Download access is enforced by the view — only the document owner
      (or an admin) may retrieve the file.  No MEDIA_URL access to documents
      is configured, so the file cannot be fetched by guessing a URL.
    · Documents are limited to 5 MB and must pass the PDF magic-byte check
      before being saved (enforced via DocumentUploadForm).
    """

    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='documents',
    )
    file = models.FileField(
        upload_to=document_upload_path,
        help_text=_('PDF document (max 5 MB)'),
    )
    original_name = models.CharField(
        max_length=255,
        help_text=_('Display name — the original filename supplied by the uploader'),
    )
    uploaded_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-uploaded_at']
        verbose_name = _('user document')
        verbose_name_plural = _('user documents')

    def __str__(self) -> str:
        return f'{self.owner.username} — {self.original_name}'
