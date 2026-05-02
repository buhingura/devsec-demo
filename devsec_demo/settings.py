"""
Django settings for devsec_demo project.

Configuration is driven entirely by environment variables so that no secret
or environment-specific value is ever committed to source control.

Quick reference — required/recommended environment variables
------------------------------------------------------------
Required in production:
  DJANGO_SECRET_KEY          Long, random, unique string (min 50 chars).
                             See: https://djecrety.ir/

Optional (shown with their defaults):
  DJANGO_DEBUG               "false"        — never set to "true" in production
  DJANGO_ALLOWED_HOSTS       "localhost,127.0.0.1"
  DJANGO_CSRF_TRUSTED_ORIGINS  ""           — comma-separated HTTPS origins
  DJANGO_DB_ENGINE           "django.db.backends.sqlite3"
  DJANGO_DB_NAME             BASE_DIR / "db.sqlite3"
  DJANGO_DB_USER             ""
  DJANGO_DB_PASSWORD         ""
  DJANGO_DB_HOST             ""
  DJANGO_DB_PORT             ""
  DJANGO_STATIC_ROOT         BASE_DIR / "staticfiles"
  DJANGO_MEDIA_ROOT          BASE_DIR / "media"
  DJANGO_EMAIL_BACKEND       "django.core.mail.backends.console.EmailBackend"
  DEFAULT_FROM_EMAIL         "noreply@localhost"
  SECURE_SSL_REDIRECT        "false"        — set "true" behind HTTPS
  SECURE_HSTS_SECONDS        "0"            — set ≥31536000 once HTTPS is stable

See .env.example for a ready-to-use development template.
"""

import os
from pathlib import Path

from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Load .env (silently ignored if the file is absent — production envs inject
# vars directly into the process environment via their platform tooling).
# ---------------------------------------------------------------------------
load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent


# ===========================================================================
# 1. SECRET KEY
# ===========================================================================
# Production deployments MUST set DJANGO_SECRET_KEY.  An absent or empty key
# raises ImproperlyConfigured immediately at startup rather than serving
# requests with a trivially guessable key.
#
# Why not a hardcoded fallback?
#   A fallback value — however long — would be committed to source control and
#   shared across every checkout.  Anyone who can read the repo (including
#   former contributors or public forks) could forge session cookies and CSRF
#   tokens.  Failing loudly is safer than silently degrading.

_secret_key = os.environ.get('DJANGO_SECRET_KEY', '')
if not _secret_key:
    raise ValueError(
        "DJANGO_SECRET_KEY environment variable is not set. "
        "Generate one with: python -c \"import secrets; print(secrets.token_urlsafe(64))\" "
        "and export it before starting the server."
    )
SECRET_KEY = _secret_key


# ===========================================================================
# 2. DEBUG
# ===========================================================================
# os.environ.get() always returns a STRING.  Casting the raw string directly
# to bool() is a silent security bug: bool('False') == True.
# The canonical pattern is an explicit string comparison.
#
# Default: False — safest assumption.  Must be explicitly opted-in for dev.

DEBUG = os.environ.get('DJANGO_DEBUG', 'false').strip().lower() in {'1', 'true', 'yes'}


# ===========================================================================
# 3. ALLOWED HOSTS
# ===========================================================================
# Restricts which HTTP Host headers Django will accept.  Without this, an
# attacker can perform HTTP Host header injection attacks.
#
# Value: comma-separated hostnames/IPs.
# Production example: "myapp.com,www.myapp.com"
# Development default: "localhost,127.0.0.1"

_raw_hosts = os.environ.get('DJANGO_ALLOWED_HOSTS', 'localhost,127.0.0.1')
ALLOWED_HOSTS = [h.strip() for h in _raw_hosts.split(',') if h.strip()]


# ===========================================================================
# 4. APPLICATION DEFINITION
# ===========================================================================

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    # Project app
    'idan_muteruz',
]

# SecurityMiddleware must be first — it handles HTTPS redirects and sets
# several security response headers before any other middleware runs.
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'devsec_demo.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'devsec_demo.wsgi.application'


# ===========================================================================
# 5. DATABASE
# ===========================================================================
# Defaults to SQLite for development.  Production deployments should set
# DJANGO_DB_ENGINE (e.g. "django.db.backends.postgresql") and the other
# DB_* variables.

DATABASES = {
    'default': {
        'ENGINE': os.environ.get(
            'DJANGO_DB_ENGINE',
            'django.db.backends.sqlite3',
        ),
        'NAME': os.environ.get(
            'DJANGO_DB_NAME',
            str(BASE_DIR / 'db.sqlite3'),
        ),
        'USER':     os.environ.get('DJANGO_DB_USER', ''),
        'PASSWORD': os.environ.get('DJANGO_DB_PASSWORD', ''),
        'HOST':     os.environ.get('DJANGO_DB_HOST', ''),
        'PORT':     os.environ.get('DJANGO_DB_PORT', ''),
    }
}

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'


# ===========================================================================
# 6. PASSWORD VALIDATION
# ===========================================================================

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]


# ===========================================================================
# 7. INTERNATIONALISATION
# ===========================================================================

LANGUAGE_CODE = 'en-us'
TIME_ZONE     = 'UTC'
USE_I18N      = True
USE_TZ        = True


# ===========================================================================
# 8. STATIC & MEDIA FILES
# ===========================================================================

STATIC_URL  = '/static/'
STATIC_ROOT = os.environ.get('DJANGO_STATIC_ROOT', str(BASE_DIR / 'staticfiles'))

MEDIA_URL  = '/media/'
MEDIA_ROOT = os.environ.get('DJANGO_MEDIA_ROOT', str(BASE_DIR / 'media'))


# ===========================================================================
# 9. EMAIL
# ===========================================================================
# Console backend for development; override to SMTP or a transactional
# provider in production.

EMAIL_BACKEND   = os.environ.get(
    'DJANGO_EMAIL_BACKEND',
    'django.core.mail.backends.console.EmailBackend',
)
DEFAULT_FROM_EMAIL = os.environ.get('DEFAULT_FROM_EMAIL', 'noreply@localhost')



# ===========================================================================
# 10. AUTHENTICATION REDIRECTS
# ===========================================================================

LOGIN_URL           = '/login/'
LOGIN_REDIRECT_URL  = '/dashboard/'
LOGOUT_REDIRECT_URL = '/login/'


# ===========================================================================
# 11. COOKIE & SESSION SECURITY
# ===========================================================================

_cookie_secure = os.environ.get('DJANGO_COOKIE_SECURE', 'false').strip().lower() in {
    '1', 'true', 'yes',
}

SESSION_COOKIE_SECURE   = _cookie_secure
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
SESSION_COOKIE_AGE      = 1800                    # 30 minutes

CSRF_COOKIE_SECURE      = _cookie_secure
CSRF_COOKIE_HTTPONLY    = True
CSRF_COOKIE_SAMESITE    = 'Lax'

_csrf_origins = os.environ.get('DJANGO_CSRF_TRUSTED_ORIGINS', '')
CSRF_TRUSTED_ORIGINS = [o.strip() for o in _csrf_origins.split(',') if o.strip()]


# ===========================================================================
# 12. TRANSPORT SECURITY (HTTPS / HSTS)
# ===========================================================================

SECURE_SSL_REDIRECT = os.environ.get('SECURE_SSL_REDIRECT', 'false').strip().lower() in {
    '1', 'true', 'yes',
}

SECURE_PROXY_SSL_HEADER = (
    ('HTTP_X_FORWARDED_PROTO', 'https')
    if os.environ.get('DJANGO_TRUST_PROXY_SSL', 'false').strip().lower() in {'1', 'true', 'yes'}
    else None
)

SECURE_HSTS_SECONDS            = int(os.environ.get('SECURE_HSTS_SECONDS', '0'))
SECURE_HSTS_INCLUDE_SUBDOMAINS = os.environ.get(
    'SECURE_HSTS_INCLUDE_SUBDOMAINS', 'false'
).strip().lower() in {'1', 'true', 'yes'}
SECURE_HSTS_PRELOAD            = os.environ.get(
    'SECURE_HSTS_PRELOAD', 'false'
).strip().lower() in {'1', 'true', 'yes'}


# ===========================================================================
# 13. ADDITIONAL SECURITY HEADERS
# ===========================================================================

SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_BROWSER_XSS_FILTER   = True
X_FRAME_OPTIONS              = 'DENY'
SECURE_REFERRER_POLICY       = 'strict-origin-when-cross-origin'


# ===========================================================================
# 14. BRUTE-FORCE / LOGIN THROTTLING
# ===========================================================================

LOGIN_MAX_ATTEMPTS    = int(os.environ.get('LOGIN_MAX_ATTEMPTS', '5'))
LOGIN_LOCKOUT_SECONDS = int(os.environ.get('LOGIN_LOCKOUT_SECONDS', '900'))

PASSWORD_RESET_TIMEOUT = int(os.environ.get('PASSWORD_RESET_TIMEOUT', '3600'))


# ===========================================================================
# 15. FILE UPLOAD LIMITS
# ===========================================================================

AVATAR_MAX_UPLOAD_BYTES   = int(os.environ.get('AVATAR_MAX_UPLOAD_BYTES',   str(2 * 1024 * 1024)))
DOCUMENT_MAX_UPLOAD_BYTES = int(os.environ.get('DOCUMENT_MAX_UPLOAD_BYTES', str(5 * 1024 * 1024)))


# ===========================================================================
# 16. AUDIT LOGGING
# ===========================================================================

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'audit': {
            'format':  '%(asctime)s %(levelname)s [audit] %(message)s',
            'datefmt': '%Y-%m-%dT%H:%M:%SZ',
        },
        'verbose': {
            'format': '%(asctime)s %(levelname)s %(name)s %(message)s',
        },
    },
    'handlers': {
        'audit_console': {
            'class':     'logging.StreamHandler',
            'formatter': 'audit',
            'level':     'INFO',
        },
        'console': {
            'class':     'logging.StreamHandler',
            'formatter': 'verbose',
            'level':     'WARNING',
        },
    },
    'loggers': {
        'idan_muteruz.audit': {
            'handlers':  ['audit_console'],
            'level':     'INFO',
            'propagate': False,
        },
        'django': {
            'handlers':  ['console'],
            'level':     'WARNING',
            'propagate': False,
        },
    },
}
