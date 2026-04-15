from django.conf import settings
from django.db import models
from django.utils.translation import gettext_lazy as _


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
