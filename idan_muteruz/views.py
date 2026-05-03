import os
from datetime import timedelta
from urllib.parse import urlencode

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import get_user_model, login
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import FileResponse, Http404
from django.contrib.auth.models import Group
from django.contrib.auth.views import (
    LoginView,
    LogoutView,
    PasswordChangeView,
    PasswordResetView,
    PasswordResetDoneView,
    PasswordResetConfirmView,
    PasswordResetCompleteView,
)
from django.contrib.messages.views import SuccessMessageMixin
from django.core.exceptions import PermissionDenied
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse, reverse_lazy
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.generic import FormView, RedirectView, TemplateView, View

from . import audit
from .forms import (
    AssignRoleForm,
    AvatarUploadForm,
    DocumentUploadForm,
    ProfileForm,
    RegistrationForm,
    CustomPasswordChangeForm,
    UserUpdateForm,
)
from .mixins import PrivilegedAccessMixin, StaffRequiredMixin
from .models import LoginAttempt, UserDocument

User = get_user_model()

# ---------------------------------------------------------------------------
# Brute-force protection helpers
# ---------------------------------------------------------------------------

def _lockout_window() -> timedelta:
    return timedelta(seconds=getattr(settings, 'LOGIN_LOCKOUT_SECONDS', 900))


def _max_attempts() -> int:
    return getattr(settings, 'LOGIN_MAX_ATTEMPTS', 5)


def _recent_failures(username: str) -> int:
    """Count failed login attempts for *username* within the lockout window."""
    since = timezone.now() - _lockout_window()
    return LoginAttempt.objects.filter(
        username__iexact=username,
        succeeded=False,
        timestamp__gte=since,
    ).count()


def _lockout_expires_at(username: str):
    """Return the datetime when the lockout expires, or None."""
    since = timezone.now() - _lockout_window()
    oldest = (
        LoginAttempt.objects
        .filter(username__iexact=username, succeeded=False, timestamp__gte=since)
        .order_by('timestamp')
        .first()
    )
    return (oldest.timestamp + _lockout_window()) if oldest else None


def _get_client_ip(request) -> str | None:
    """
    Return the client's IP address from the request.

    REMOTE_ADDR is the direct-connection IP — reliable when Django sits
    behind a trusted reverse proxy that sets X-Forwarded-For.  In this
    app there is no proxy configuration, so REMOTE_ADDR is used directly.
    Recorded for audit purposes only; lockout is not IP-scoped.
    """
    return request.META.get('REMOTE_ADDR')


# ---------------------------------------------------------------------------
# Open-redirect guard
# ---------------------------------------------------------------------------

def _safe_next_url(request, fallback: str = '') -> str:
    """
    Return the ``next`` parameter from the request only if it is a safe,
    same-host URL.  Returns *fallback* for any URL that does not pass the
    safety check.

    Safety check (Django's ``url_has_allowed_host_and_scheme``):
    · Rejects absolute URLs pointing to other hosts  (``http://evil.com/``)
    · Rejects protocol-relative URLs                 (``//evil.com/``)
    · Rejects empty/None values
    · Accepts absolute paths on the same host        (``/dashboard/``)
    · When the current request is HTTPS, rejects any non-HTTPS target

    POST is checked before GET so that the hidden form field takes
    precedence over the query string.
    """
    url = request.POST.get('next') or request.GET.get('next', '')
    if url and url_has_allowed_host_and_scheme(
        url=url,
        allowed_hosts={request.get_host()},
        require_https=request.is_secure(),
    ):
        return url
    return fallback


class HomeRedirectView(RedirectView):
    pattern_name = 'idan_muteruz:login'
    permanent = False

    def get_redirect_url(self, *args, **kwargs):
        if self.request.user.is_authenticated:
            return reverse_lazy('idan_muteruz:dashboard')
        return super().get_redirect_url(*args, **kwargs)


class RegisterView(FormView):
    """
    Registration view.

    Open-redirect note:
    A ``next`` parameter may arrive in the query string when an
    unauthenticated user is redirected from a protected page to register
    (e.g. ``/register/?next=/dashboard/``).  After successful registration
    the user still needs to sign in, so we forward them to the login page.
    If a validated ``next`` URL is present we append it to the login URL so
    the user reaches their intended destination after signing in.

    Validation is performed by ``_safe_next_url()``, which calls Django's
    ``url_has_allowed_host_and_scheme``.  Any URL that does not pass —
    external hosts, protocol-relative URLs — is silently discarded and the
    user lands on plain ``/login/``.
    """

    template_name = 'idan_muteruz/register.html'
    form_class = RegistrationForm

    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return redirect('idan_muteruz:dashboard')
        return super().dispatch(request, *args, **kwargs)

    def get_success_url(self):
        login_url = reverse('idan_muteruz:login')
        next_url = _safe_next_url(self.request)
        if next_url:
            return f'{login_url}?{urlencode({"next": next_url})}'
        return login_url

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        # Expose the validated next URL to the template so the hidden field
        # can survive the POST → redirect chain without re-reading raw input.
        context['next'] = _safe_next_url(self.request)
        return context

    def form_valid(self, form):
        user = form.save()
        audit.log('REGISTER', self.request, username=user.username, email=user.email)
        messages.success(self.request, 'Account created successfully. Please sign in.')
        return super().form_valid(form)


class UserLoginView(LoginView):
    """
    Hardened login view with brute-force protection.

    Protection mechanism — account-based sliding-window lockout:

    · After LOGIN_MAX_ATTEMPTS (default 5) consecutive failures within
      LOGIN_LOCKOUT_SECONDS (default 900 s / 15 min), the account is
      temporarily locked for the remainder of that window.
    · The lockout window slides: it is anchored to the *oldest* failure in
      the current window, not to the first-ever failure.  Once that oldest
      failure falls outside the window the count drops below the threshold
      and the account unlocks automatically — no admin action required.
    · Every attempt (failure and success) is recorded in LoginAttempt for
      audit purposes.  On a successful login, previous failure records for
      the account are cleared so a single typo before a correct password
      does not accumulate toward the next lockout.

    Why account-scoping instead of IP-scoping:
    · IP blocking causes collateral damage for users behind shared NAT
      (a classroom, a home router) and is easily bypassed with a new IP.
    · Account-scoping precisely targets the account under attack without
      affecting other users, and forces a real slow-down on credential
      stuffing even when the attacker rotates IPs.

    Usability choices:
    · The lockout message shows the remaining wait time in whole minutes
      so a legitimate user knows exactly how long to wait.
    · The counter resets on a successful login; a user who makes one typo
      then succeeds is not penalised on subsequent sessions.
    · The lockout is enforced before the form is submitted to Django's
      authentication backend, so locked accounts are never queried.

    Open-redirect protection:
    · ``next`` parameter validation is handled by the parent class through
      ``RedirectURLMixin.get_redirect_url()``, which calls Django's
      ``url_has_allowed_host_and_scheme``.  Any external or protocol-relative
      URL is rejected and the user is sent to ``next_page`` (dashboard)
      instead.  No override is needed here — the protection is structural.
    · The lockout-redirect path below uses ``_safe_next_url()`` to preserve
      a validated ``next`` value across the lockout bounce so that a
      legitimate user does not lose their intended destination.
    """

    template_name = 'idan_muteruz/login.html'
    redirect_authenticated_user = True
    next_page = reverse_lazy('idan_muteruz:dashboard')

    def post(self, request, *args, **kwargs):
        username = request.POST.get('username', '').strip()
        if username and _recent_failures(username) >= _max_attempts():
            expires_at = _lockout_expires_at(username)
            if expires_at:
                remaining_secs = (expires_at - timezone.now()).total_seconds()
                remaining_mins = max(int(remaining_secs // 60) + 1, 1)
                wait_msg = f'Please try again in {remaining_mins} minute(s).'
            else:
                wait_msg = 'Please try again later.'
            audit.log('LOGIN_LOCKED', request, username=username, remaining_mins=remaining_mins if expires_at else '?')
            messages.error(
                request,
                f'Too many failed sign-in attempts. {wait_msg}',
            )
            # Preserve a validated next URL across the lockout bounce so the
            # user does not lose their destination.  _safe_next_url() rejects
            # any external or protocol-relative URL before it enters the
            # redirect target, preventing open-redirect via the lockout path.
            login_url = reverse('idan_muteruz:login')
            next_url = _safe_next_url(request)
            if next_url:
                login_url = f'{login_url}?{urlencode({"next": next_url})}'
            return redirect(login_url)
        return super().post(request, *args, **kwargs)

    def form_invalid(self, form):
        """Called by Django's LoginView when authentication fails."""
        username = self.request.POST.get('username', '').strip()
        LoginAttempt.objects.create(
            username=username,
            ip_address=_get_client_ip(self.request),
            succeeded=False,
        )
        audit.log('LOGIN_FAILURE', self.request, username=username)
        return super().form_invalid(form)

    def form_valid(self, form):
        """Called by Django's LoginView after successful authentication."""
        username = form.cleaned_data.get('username', '')
        # Clear previous failures so the counter resets after a successful login.
        LoginAttempt.objects.filter(username__iexact=username, succeeded=False).delete()
        # Record the success for the audit log.
        LoginAttempt.objects.create(
            username=username,
            ip_address=_get_client_ip(self.request),
            succeeded=True,
        )
        audit.log('LOGIN_SUCCESS', self.request, username=username)
        return super().form_valid(form)


class UserLogoutView(LogoutView):
    next_page = reverse_lazy('idan_muteruz:login')
    # Explicitly restrict to POST only.
    #
    # Django 5.0 removed GET-based logout (deprecated in 4.1).  The parent
    # class already sets http_method_names = ["post", "options"].  We
    # re-state the restriction here to make the intent unambiguous:
    # · GET/HEAD are excluded — a bare hyperlink or <img> tag must not be
    #   able to trigger a logout (classic CSRF via safe methods).
    # · TRACE is excluded — HTTP TRACE echoes request headers, including
    #   cookies, back to the caller; enabling it is a Cross-Site Tracing
    #   (XST) anti-pattern even though modern browsers block TRACE via XHR.
    http_method_names = ['post', 'options']

    def post(self, request, *args, **kwargs):
        # Capture the username BEFORE the parent clears request.user.
        # Django's LogoutView calls auth_logout(request) which replaces
        # request.user with AnonymousUser, so we must read it first.
        username = request.user.username if request.user.is_authenticated else ''
        response = super().post(request, *args, **kwargs)
        audit.log('LOGOUT', request, username=username)
        return response


class DashboardView(LoginRequiredMixin, TemplateView):
    template_name = 'idan_muteruz/dashboard.html'
    login_url = reverse_lazy('idan_muteruz:login')


class ProfileView(LoginRequiredMixin, TemplateView):
    template_name = 'idan_muteruz/profile.html'
    login_url = reverse_lazy('idan_muteruz:login')

    # IDOR note: there is no identifier in the URL.  Every read and write here
    # is explicitly scoped to request.user / request.user.profile, so it is
    # structurally impossible for one user to view or modify another user's
    # profile through this endpoint.

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['user_form'] = UserUpdateForm(
            instance=self.request.user,          # always the logged-in user
            user=self.request.user,
        )
        context['profile_form'] = ProfileForm(instance=self.request.user.profile)
        return context

    def post(self, request, *args, **kwargs):
        user_form = UserUpdateForm(
            request.POST,
            instance=request.user,               # always the logged-in user
            user=request.user,
        )
        profile_form = ProfileForm(
            request.POST,
            instance=request.user.profile,       # always the logged-in user's profile
        )

        if user_form.is_valid() and profile_form.is_valid():
            user_form.save()
            profile_form.save()
            messages.success(request, 'Your profile has been updated successfully.')
            return redirect('idan_muteruz:profile')

        return self.render_to_response(
            self.get_context_data(user_form=user_form, profile_form=profile_form)
        )


class UserPasswordChangeView(SuccessMessageMixin, LoginRequiredMixin, PasswordChangeView):
    template_name = 'idan_muteruz/password_change.html'
    form_class = CustomPasswordChangeForm
    success_url = reverse_lazy('idan_muteruz:profile')
    success_message = 'Your password has been changed successfully.'
    login_url = reverse_lazy('idan_muteruz:login')

    # IDOR note: Django's PasswordChangeView always binds form.user = request.user
    # (see django/contrib/auth/views.py).  There is no pk or username in the URL,
    # so this view cannot be used to change another user's password.

    def form_valid(self, form):
        audit.log('PASSWORD_CHANGE', self.request, username=self.request.user.username)
        return super().form_valid(form)


class AdminPanelView(PrivilegedAccessMixin, TemplateView):
    """
    Restricted view for staff, superusers, and users granted the
    ``idan_muteruz.can_access_admin_panel`` permission (e.g. instructors).

    Unauthenticated users              → redirect to login
    Authenticated without privilege    → HTTP 403 Forbidden
    """

    template_name = 'idan_muteruz/admin_panel.html'
    permission_required = 'idan_muteruz.can_access_admin_panel'
    login_url = reverse_lazy('idan_muteruz:login')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        groups = Group.objects.prefetch_related('user_set').all()
        context['groups'] = [
            {
                'group': g,
                'user_count': g.user_set.count(),
                'users': g.user_set.all()[:10],
            }
            for g in groups
        ]

        # User Management table — only surfaced to staff / superusers.
        if self.request.user.is_staff or self.request.user.is_superuser:
            users_qs = (
                User.objects
                .prefetch_related('groups')
                .order_by('username')
            )
            context['user_rows'] = [
                {
                    'user': u,
                    'current_group': u.groups.first(),
                    'form': AssignRoleForm(
                        initial={'group': u.groups.first()},
                        prefix=f'user_{u.pk}',
                    ),
                }
                for u in users_qs
            ]
        return context


class AssignRoleView(StaffRequiredMixin, View):
    """
    POST-only endpoint: replaces a target user's group membership with one
    chosen group.

    Route-level guard: StaffRequiredMixin (is_staff or is_superuser).

    Object-level guards (applied after fetching the target user by pk):
        1. Superusers cannot be targeted — their accounts are managed via
           Django admin, not this endpoint.  Returns 403.
        2. Only superusers may modify another staff user's group.  A plain
           staff member cannot escalate or de-escalate peers.  Returns 403.
        3. No actor may reassign their own group — prevents self-escalation.
           Returns 403.

    WHY 403 (not 404) for these checks:
        The target user is already listed in the admin panel table that the
        actor can see.  Pretending the user doesn't exist would be confusing
        rather than protective.  404 is reserved for genuinely missing objects
        (handled by get_object_or_404 above the checks).
    """

    login_url = reverse_lazy('idan_muteruz:login')
    http_method_names = ['post']

    def post(self, request, pk):
        # Non-existent pk → 404 (reveals nothing about other valid pks).
        target_user = get_object_or_404(User, pk=pk)

        # ── Object-level authorization ────────────────────────────────────────
        # Check 1: superuser accounts are off-limits to everyone via this view.
        if target_user.is_superuser:
            raise PermissionDenied

        # Check 2: modifying a staff member's groups requires superuser status.
        if target_user.is_staff and not request.user.is_superuser:
            raise PermissionDenied

        # Check 3: no one may reassign their own role (self-escalation guard).
        if target_user == request.user:
            raise PermissionDenied
        # ─────────────────────────────────────────────────────────────────────

        form = AssignRoleForm(request.POST, prefix=f'user_{pk}')
        if form.is_valid():
            old_group = target_user.groups.first()
            group = form.cleaned_data['group']
            target_user.groups.set([group])
            audit.log(
                'ROLE_CHANGE',
                request,
                actor=request.user.username,
                target=target_user.username,
                old_group=old_group.name if old_group else 'none',
                new_group=group.name,
            )
            messages.success(
                request,
                f"Role updated: {target_user.username} → {group.name}",
            )
        else:
            messages.error(request, "Invalid role selection. Please try again.")

        return redirect('idan_muteruz:admin_panel')


# ---------------------------------------------------------------------------
# Password reset flow (4-step Django built-in flow, hardened)
# ---------------------------------------------------------------------------

class UserPasswordResetView(PasswordResetView):
    """
    Step 1 — user submits their e-mail address.

    Security notes:
    · Uses a dedicated subject and body template so we control the exact
      content of the reset e-mail (no subject-line injection via newlines
      in the template, since Django strips newlines from the subject, but
      using a .txt template makes the intent explicit).
    · ``from_email`` is set from DEFAULT_FROM_EMAIL so it can be
      overridden per-environment without touching code.
    · The view does NOT reveal whether an e-mail address is registered:
      Django's PasswordResetView always redirects to the "sent" page
      regardless of whether the address was found, preventing user
      enumeration through this endpoint.
    """

    template_name = 'idan_muteruz/password_reset_request.html'
    email_template_name = 'idan_muteruz/email/password_reset_body.txt'
    subject_template_name = 'idan_muteruz/email/password_reset_subject.txt'
    success_url = reverse_lazy('idan_muteruz:password_reset_sent')

    def form_valid(self, form):
        # Log the submitted e-mail address, NOT whether it matched an account
        # (that distinction must never appear in logs — it would be an
        # enumeration signal if logs are shared or leaked).
        audit.log(
            'PASSWORD_RESET_REQUESTED',
            self.request,
            email=form.cleaned_data['email'],
        )
        return super().form_valid(form)


class UserPasswordResetSentView(PasswordResetDoneView):
    """Step 2 — confirmation page shown after the e-mail is dispatched."""

    template_name = 'idan_muteruz/password_reset_sent.html'


class UserPasswordResetConfirmView(PasswordResetConfirmView):
    """
    Step 3 — user follows the link from the e-mail and sets a new password.

    The ``uidb64``/``token`` pair is validated by the parent class.  An
    expired or already-used token renders the template with
    ``validlink=False`` so the user receives a clear error rather than a
    silent failure.
    """

    template_name = 'idan_muteruz/password_reset_confirm.html'
    success_url = reverse_lazy('idan_muteruz:password_reset_complete')

    def form_valid(self, form):
        # form.user is set by Django's SetPasswordForm and is the account
        # whose password is being reset.  The reset token itself is never
        # logged — only the outcome and the affected username.
        audit.log(
            'PASSWORD_RESET_COMPLETE',
            self.request,
            username=form.user.username,
        )
        return super().form_valid(form)


class UserPasswordResetCompleteView(PasswordResetCompleteView):
    """Step 4 — success page shown after the password has been changed."""

    template_name = 'idan_muteruz/password_reset_complete.html'


# ---------------------------------------------------------------------------
# File upload / download views
# ---------------------------------------------------------------------------

class AvatarUploadView(LoginRequiredMixin, View):
    """
    POST-only endpoint: replace the logged-in user's profile avatar.

    The file is validated by AvatarUploadForm (size + extension + Pillow
    verify) before being saved.  The old avatar is deleted from storage when a
    new one is accepted to prevent accumulation of orphaned files.

    Access control: LoginRequiredMixin ensures only authenticated users can
    upload.  The upload is always scoped to ``request.user.profile``, so
    one user cannot replace another user's avatar.
    """

    login_url = reverse_lazy('idan_muteruz:login')
    http_method_names = ['post']

    def post(self, request, *args, **kwargs):
        profile = request.user.profile
        # Capture the old storage path BEFORE form.is_valid() runs.
        # form._post_clean() sets profile.avatar to the new file on the
        # instance, so reading profile.avatar AFTER is_valid() would give
        # the new file, not the old one.  We capture just the name (a plain
        # string) so that FieldFile.delete() cannot accidentally reset the
        # field to None on the instance before form.save() is called.
        old_avatar_name = profile.avatar.name if profile.avatar else None
        form = AvatarUploadForm(request.POST, request.FILES, instance=profile)
        if form.is_valid():
            form.save()
            # Remove the previous avatar file from storage AFTER the new one
            # is safely written, so a storage error on cleanup never prevents
            # the upload from succeeding.
            if old_avatar_name:
                from django.core.files.storage import default_storage
                try:
                    default_storage.delete(old_avatar_name)
                except OSError:
                    pass  # stale reference — file already gone
            messages.success(request, 'Avatar updated successfully.')
        else:
            for error_list in form.errors.values():
                for error in error_list:
                    messages.error(request, error)
        return redirect('idan_muteruz:profile')


class DocumentListView(LoginRequiredMixin, TemplateView):
    """
    Lists the documents owned by the logged-in user.

    Scoped to ``request.user`` — a user can only see their own documents.
    No URL parameter is accepted; IDOR is structurally prevented.
    """

    template_name = 'idan_muteruz/documents.html'
    login_url = reverse_lazy('idan_muteruz:login')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['documents'] = UserDocument.objects.filter(owner=self.request.user)
        context['upload_form'] = DocumentUploadForm()
        return context


class DocumentUploadView(LoginRequiredMixin, View):
    """
    POST-only endpoint: upload a new private PDF document.

    The file is validated by DocumentUploadForm (size + extension + magic
    bytes) before being saved.  The ``original_name`` stored in the database
    is the client-supplied filename sanitised to its basename only —
    path components (e.g. ``../../etc/passwd``) are stripped.

    Access control: LoginRequiredMixin + always sets ``owner=request.user``.
    """

    login_url = reverse_lazy('idan_muteruz:login')
    http_method_names = ['post']

    def post(self, request, *args, **kwargs):
        form = DocumentUploadForm(request.POST, request.FILES)
        if form.is_valid():
            doc = form.save(commit=False)
            doc.owner = request.user
            # Store only the basename to prevent path-traversal payloads in
            # the display name (e.g. "../../etc/passwd.pdf" → "passwd.pdf").
            raw_name = request.FILES['file'].name
            doc.original_name = os.path.basename(raw_name)
            doc.save()
            messages.success(request, f'"{doc.original_name}" uploaded successfully.')
        else:
            for error_list in form.errors.values():
                for error in error_list:
                    messages.error(request, error)
        return redirect('idan_muteruz:documents')


class DocumentDownloadView(LoginRequiredMixin, View):
    """
    Serve a document as a file download.

    Ownership check: the document must belong to ``request.user``.  Any
    attempt to download another user's document returns 404 (not 403) to
    avoid confirming whether the document pk exists.

    FileResponse with ``as_attachment=True`` sets Content-Disposition to
    ``attachment``, which instructs the browser to download the file rather
    than render it inline.  This prevents a malicious PDF with embedded
    JavaScript from executing in the browser's PDF renderer.

    Content-Type is set explicitly to ``application/pdf`` rather than
    trusting the file extension, consistent with the upload-time validation.
    """

    login_url = reverse_lazy('idan_muteruz:login')

    def get(self, request, pk, *args, **kwargs):
        doc = get_object_or_404(UserDocument, pk=pk, owner=request.user)
        try:
            file_handle = doc.file.open('rb')
        except (OSError, FileNotFoundError):
            raise Http404('File not found on storage.')
        return FileResponse(
            file_handle,
            as_attachment=True,
            filename=doc.original_name,
            content_type='application/pdf',
        )


class DocumentDeleteView(LoginRequiredMixin, View):
    """
    POST-only endpoint: delete a document.

    Ownership check: same 404-on-mismatch pattern as DocumentDownloadView.
    After removing the database row the file is deleted from storage so no
    orphaned blobs remain.
    """

    login_url = reverse_lazy('idan_muteruz:login')
    http_method_names = ['post']

    def post(self, request, pk, *args, **kwargs):
        doc = get_object_or_404(UserDocument, pk=pk, owner=request.user)
        name = doc.original_name
        doc.file.delete(save=False)   # remove from storage
        doc.delete()                  # remove from database
        messages.success(request, f'"{name}" deleted.')
        return redirect('idan_muteruz:documents')
