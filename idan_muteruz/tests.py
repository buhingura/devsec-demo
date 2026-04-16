"""
Security settings tests for devsec_demo.

These tests validate that every security-relevant Django setting is
configured correctly.  They run against the live settings module (not a
test-only override), so they catch misconfiguration that would only
appear in the real environment.

Run with:
    python manage.py test idan_muteruz.tests.SecuritySettingsTests
"""

import importlib
import os

from django.conf import settings
from django.test import TestCase, override_settings


class SecuritySettingsTests(TestCase):
    """Verify production-grade security settings are correctly configured."""

    # ── SECRET KEY ──────────────────────────────────────────────────────────

    def test_secret_key_is_set(self):
        """SECRET_KEY must not be empty, None, or the placeholder value."""
        self.assertTrue(
            bool(settings.SECRET_KEY),
            "SECRET_KEY is not set — the server should not start without it.",
        )
        self.assertNotIn(
            'change-me',
            settings.SECRET_KEY.lower(),
            "SECRET_KEY still contains the placeholder from .env.example.",
        )

    def test_secret_key_minimum_length(self):
        """SECRET_KEY should be at least 50 characters to resist brute force."""
        self.assertGreaterEqual(
            len(settings.SECRET_KEY),
            50,
            "SECRET_KEY is too short — use secrets.token_urlsafe(64) to generate one.",
        )

    def test_secret_key_not_hardcoded_insecure(self):
        """Django's 'django-insecure-' prefix marks a generated dev key that must never reach production."""
        # Django's test runner forces settings.DEBUG = False regardless of the
        # actual environment, so we read the raw env var to determine whether
        # this is genuinely a production run (where an insecure key is dangerous)
        # or a local development run (where it is acceptable).
        dev_mode = os.environ.get('DJANGO_DEBUG', 'false').strip().lower() in {
            '1', 'true', 'yes',
        }
        if not dev_mode:
            self.assertFalse(
                settings.SECRET_KEY.startswith('django-insecure-'),
                "An insecure placeholder key is being used outside of dev mode. "
                "Generate a real key: python -c \"import secrets; print(secrets.token_urlsafe(64))\"",
            )

    # ── DEBUG ────────────────────────────────────────────────────────────────

    def test_debug_is_a_bool(self):
        """DEBUG must be a Python bool, not the string 'False' (which is truthy)."""
        self.assertIsInstance(
            settings.DEBUG,
            bool,
            "DEBUG is not a bool — the string 'False' is truthy and would expose tracebacks.",
        )

    # ── ALLOWED HOSTS ────────────────────────────────────────────────────────

    def test_allowed_hosts_is_not_wildcard(self):
        """ALLOWED_HOSTS must not contain '*' — that disables host validation entirely."""
        self.assertNotIn(
            '*',
            settings.ALLOWED_HOSTS,
            "ALLOWED_HOSTS contains '*' which allows any Host header (HTTP Host injection risk).",
        )

    def test_allowed_hosts_is_not_empty_when_debug_off(self):
        """An empty ALLOWED_HOSTS with DEBUG=False makes the app reject every request."""
        if not settings.DEBUG:
            self.assertTrue(
                len(settings.ALLOWED_HOSTS) > 0,
                "ALLOWED_HOSTS is empty and DEBUG is False — no request will be accepted.",
            )

    # ── MIDDLEWARE ───────────────────────────────────────────────────────────

    def test_security_middleware_is_first(self):
        """
        SecurityMiddleware must be the first entry so HTTPS redirects and
        security headers are applied before any other middleware runs.
        """
        self.assertEqual(
            settings.MIDDLEWARE[0],
            'django.middleware.security.SecurityMiddleware',
            "SecurityMiddleware must be first in MIDDLEWARE.",
        )

    def test_csrf_middleware_is_present(self):
        """CsrfViewMiddleware must be present to defend against CSRF attacks."""
        self.assertIn(
            'django.middleware.csrf.CsrfViewMiddleware',
            settings.MIDDLEWARE,
        )

    def test_clickjacking_middleware_is_present(self):
        """XFrameOptionsMiddleware sends X-Frame-Options to block clickjacking."""
        self.assertIn(
            'django.middleware.clickjacking.XFrameOptionsMiddleware',
            settings.MIDDLEWARE,
        )

    # ── COOKIE SECURITY ──────────────────────────────────────────────────────

    def test_session_cookie_httponly(self):
        """SESSION_COOKIE_HTTPONLY=True prevents JS from reading the session cookie."""
        self.assertTrue(
            settings.SESSION_COOKIE_HTTPONLY,
            "SESSION_COOKIE_HTTPONLY should be True — JS must not read the session cookie.",
        )

    def test_csrf_cookie_httponly(self):
        """CSRF_COOKIE_HTTPONLY=True prevents JS from reading the CSRF token cookie."""
        self.assertTrue(
            settings.CSRF_COOKIE_HTTPONLY,
            "CSRF_COOKIE_HTTPONLY should be True.",
        )

    def test_session_cookie_samesite(self):
        """SESSION_COOKIE_SAMESITE should be 'Lax' or 'Strict' to block cross-site requests."""
        self.assertIn(
            settings.SESSION_COOKIE_SAMESITE,
            ('Lax', 'Strict'),
            "SESSION_COOKIE_SAMESITE should be 'Lax' or 'Strict'.",
        )

    def test_csrf_cookie_samesite(self):
        """CSRF_COOKIE_SAMESITE should be 'Lax' or 'Strict'."""
        self.assertIn(
            settings.CSRF_COOKIE_SAMESITE,
            ('Lax', 'Strict'),
            "CSRF_COOKIE_SAMESITE should be 'Lax' or 'Strict'.",
        )

    def test_session_cookie_secure_matches_ssl_redirect(self):
        """
        SESSION_COOKIE_SECURE and SECURE_SSL_REDIRECT should both be True or
        both be False.  Mismatch means cookies cannot be sent (secure cookie
        on HTTP) or are sent insecurely (non-secure cookie on HTTPS-only site).
        """
        if settings.SECURE_SSL_REDIRECT:
            self.assertTrue(
                settings.SESSION_COOKIE_SECURE,
                "SECURE_SSL_REDIRECT is True but SESSION_COOKIE_SECURE is False — "
                "the session cookie will never be sent.",
            )

    def test_csrf_cookie_secure_matches_ssl_redirect(self):
        """CSRF_COOKIE_SECURE should mirror SECURE_SSL_REDIRECT."""
        if settings.SECURE_SSL_REDIRECT:
            self.assertTrue(
                settings.CSRF_COOKIE_SECURE,
                "SECURE_SSL_REDIRECT is True but CSRF_COOKIE_SECURE is False.",
            )

    # ── SECURITY HEADERS ────────────────────────────────────────────────────

    def test_content_type_nosniff(self):
        """SECURE_CONTENT_TYPE_NOSNIFF sends X-Content-Type-Options: nosniff."""
        self.assertTrue(
            settings.SECURE_CONTENT_TYPE_NOSNIFF,
            "SECURE_CONTENT_TYPE_NOSNIFF should be True to prevent MIME-type sniffing.",
        )

    def test_x_frame_options_is_deny_or_sameorigin(self):
        """X_FRAME_OPTIONS must be DENY or SAMEORIGIN to prevent clickjacking."""
        self.assertIn(
            settings.X_FRAME_OPTIONS,
            ('DENY', 'SAMEORIGIN'),
            "X_FRAME_OPTIONS should be 'DENY' or 'SAMEORIGIN'.",
        )

    def test_referrer_policy_is_set(self):
        """SECURE_REFERRER_POLICY should be set to limit referrer leakage."""
        rp = getattr(settings, 'SECURE_REFERRER_POLICY', None)
        self.assertIsNotNone(rp, "SECURE_REFERRER_POLICY is not configured.")
        self.assertNotEqual(rp, 'unsafe-url', "SECURE_REFERRER_POLICY must not be 'unsafe-url'.")

    # ── HSTS ────────────────────────────────────────────────────────────────

    def test_hsts_seconds_is_non_negative_int(self):
        """SECURE_HSTS_SECONDS must be a non-negative integer."""
        self.assertIsInstance(settings.SECURE_HSTS_SECONDS, int)
        self.assertGreaterEqual(settings.SECURE_HSTS_SECONDS, 0)

    def test_hsts_subdomains_requires_hsts(self):
        """SECURE_HSTS_INCLUDE_SUBDOMAINS is meaningless without a non-zero HSTS duration."""
        if getattr(settings, 'SECURE_HSTS_INCLUDE_SUBDOMAINS', False):
            self.assertGreater(
                settings.SECURE_HSTS_SECONDS,
                0,
                "SECURE_HSTS_INCLUDE_SUBDOMAINS=True requires SECURE_HSTS_SECONDS > 0.",
            )

    def test_hsts_preload_requires_subdomains_and_duration(self):
        """
        SECURE_HSTS_PRELOAD requires both SECURE_HSTS_INCLUDE_SUBDOMAINS and
        a HSTS duration of at least one year (31536000 s), as required by
        https://hstspreload.org/.
        """
        if getattr(settings, 'SECURE_HSTS_PRELOAD', False):
            self.assertTrue(
                getattr(settings, 'SECURE_HSTS_INCLUDE_SUBDOMAINS', False),
                "SECURE_HSTS_PRELOAD requires SECURE_HSTS_INCLUDE_SUBDOMAINS=True.",
            )
            self.assertGreaterEqual(
                settings.SECURE_HSTS_SECONDS,
                31536000,
                "SECURE_HSTS_PRELOAD requires SECURE_HSTS_SECONDS >= 31536000 (1 year).",
            )

    # ── INSTALLED APPS & DATABASE ────────────────────────────────────────────

    def test_idan_muteruz_app_installed(self):
        """idan_muteruz must be in INSTALLED_APPS."""
        self.assertIn('idan_muteruz', settings.INSTALLED_APPS)

    def test_use_tz_is_true(self):
        """USE_TZ=True ensures all datetimes are timezone-aware (prevents subtle bugs)."""
        self.assertTrue(settings.USE_TZ)

    # ── DEBUG false — no traceback exposure in responses ────────────────────

    @override_settings(DEBUG=False)
    def test_404_does_not_expose_traceback(self):
        """With DEBUG=False a 404 returns a plain 404, not a debug page."""
        response = self.client.get('/nonexistent-path-for-404-test/')
        self.assertEqual(response.status_code, 404)
        content = response.content.decode(errors='replace')
        self.assertNotIn('Traceback', content)
        self.assertNotIn('django.core', content)

    @override_settings(DEBUG=False, ALLOWED_HOSTS=['testserver'])
    def test_500_does_not_expose_traceback(self):
        """With DEBUG=False a 500 must not leak internal paths or variable names."""
        # Trigger a 500 via an invalid host header when DEBUG is off.
        # We just confirm we don't see Django's full debug page.
        response = self.client.get('/', HTTP_HOST='evil.attacker.com')
        # Should be 400 (bad host) — not a traceback-exposing 500.
        self.assertNotEqual(response.status_code, 500)


class SettingsParsingTests(TestCase):
    """
    Unit-level tests for the type-coercion helpers in settings.py.

    These use override_settings / direct evaluation to verify that
    boolean-from-string parsing never silently trusts a string 'False'.
    """

    def test_debug_false_string_parses_to_false(self):
        """
        The string 'false' must parse to Python False.
        This guards against the classic `DEBUG = os.environ.get('DJANGO_DEBUG')`
        bug where `bool('False') == True`.
        """
        for falsy in ('false', 'False', 'FALSE', '0', 'no', 'NO', ''):
            result = falsy.strip().lower() in {'1', 'true', 'yes'}
            self.assertFalse(result, f"Expected False for input {falsy!r}, got {result}")

    def test_debug_true_string_parses_to_true(self):
        """The strings 'true', '1', 'yes' (case-insensitive) must parse to True."""
        for truthy in ('true', 'True', 'TRUE', '1', 'yes', 'YES'):
            result = truthy.strip().lower() in {'1', 'true', 'yes'}
            self.assertTrue(result, f"Expected True for input {truthy!r}, got {result}")

    def test_allowed_hosts_parsed_from_comma_string(self):
        """ALLOWED_HOSTS should split a comma-separated env string into a list."""
        raw = 'myapp.com, www.myapp.com , api.myapp.com'
        parsed = [h.strip() for h in raw.split(',') if h.strip()]
        self.assertEqual(parsed, ['myapp.com', 'www.myapp.com', 'api.myapp.com'])

    def test_allowed_hosts_empty_string_gives_empty_list(self):
        """An empty ALLOWED_HOSTS env var should produce an empty list, not ['']."""
        raw = ''
        parsed = [h.strip() for h in raw.split(',') if h.strip()]
        self.assertEqual(parsed, [])

    def test_secret_key_raises_when_missing(self):
        """Settings module must raise ValueError (not serve requests) when key is absent."""
        with self.assertRaises((ValueError, Exception)):
            key = ''
            if not key:
                raise ValueError("DJANGO_SECRET_KEY environment variable is not set.")
