"""
Audit logging for security-relevant events.

Logger name:  ``idan_muteruz.audit``
Log level:    INFO for all events below

Log format (one line per event)
--------------------------------
  <EVENT> key=value [key=value …]

Events emitted (see views.py for call sites)
---------------------------------------------
  REGISTER                  A new user account was created.
  LOGIN_SUCCESS             A user authenticated successfully.
  LOGIN_FAILURE             An authentication attempt was rejected (wrong credentials).
  LOGIN_LOCKED              A request was blocked by the brute-force lockout guard.
  LOGOUT                    A user session was terminated.
  PASSWORD_CHANGE           An authenticated user changed their own password.
  PASSWORD_RESET_REQUESTED  A user submitted the password-reset e-mail form.
  PASSWORD_RESET_COMPLETE   A user set a new password via the reset link.
  ROLE_CHANGE               A staff member or superuser changed a user's group.

What is NEVER logged
---------------------
  · Passwords or password hashes (raw or hashed form)
  · Session IDs or authentication tokens
  · Password reset tokens (uidb64 / token pairs)
  · HTTP cookies or Authorization headers

Note on e-mail addresses
-------------------------
E-mail addresses appear in REGISTER and PASSWORD_RESET_REQUESTED records
because they are needed to correlate events with a user.  They are considered
PII and should be handled accordingly if logs are shipped to external systems.
"""
import logging

_logger = logging.getLogger('idan_muteruz.audit')


def _ip(request) -> str:
    """Return the caller's IP from REMOTE_ADDR (the direct-connection address)."""
    return request.META.get('REMOTE_ADDR', '')


def log(event: str, request, **fields) -> None:
    """
    Emit one INFO-level audit record for *event*.

    *fields* are included as ``key=value`` pairs in the message for grep-
    ability, and also attached to the LogRecord via ``extra`` for structured
    log processors (e.g. JSON formatters, log aggregators).

    The caller's IP is added automatically from ``request.REMOTE_ADDR``
    unless ``ip`` is already present in *fields*.
    """
    fields.setdefault('ip', _ip(request))
    kv = ' '.join(f'{k}={v}' for k, v in fields.items())
    _logger.info(
        '%s %s',
        event,
        kv,
        extra={'audit_event': event, 'audit_fields': fields},
    )
