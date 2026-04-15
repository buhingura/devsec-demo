from datetime import timedelta

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import get_user_model, login
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.models import Group
from django.contrib.auth.views import LoginView, LogoutView, PasswordChangeView
from django.contrib.messages.views import SuccessMessageMixin
from django.core.exceptions import PermissionDenied
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse_lazy
from django.utils import timezone
from django.views.generic import FormView, RedirectView, TemplateView, View

from .forms import (
    AssignRoleForm,
    ProfileForm,
    RegistrationForm,
    CustomPasswordChangeForm,
    UserUpdateForm,
)
from .mixins import PrivilegedAccessMixin, StaffRequiredMixin
from .models import LoginAttempt

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


class HomeRedirectView(RedirectView):
    pattern_name = 'idan_muteruz:login'
    permanent = False

    def get_redirect_url(self, *args, **kwargs):
        if self.request.user.is_authenticated:
            return reverse_lazy('idan_muteruz:dashboard')
        return super().get_redirect_url(*args, **kwargs)


class RegisterView(FormView):
    template_name = 'idan_muteruz/register.html'
    form_class = RegistrationForm
    success_url = reverse_lazy('idan_muteruz:login')

    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return redirect('idan_muteruz:dashboard')
        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        user = form.save()
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
            messages.error(
                request,
                f'Too many failed sign-in attempts. {wait_msg}',
            )
            return redirect('idan_muteruz:login')
        return super().post(request, *args, **kwargs)

    def form_invalid(self, form):
        """Called by Django's LoginView when authentication fails."""
        username = self.request.POST.get('username', '').strip()
        LoginAttempt.objects.create(
            username=username,
            ip_address=_get_client_ip(self.request),
            succeeded=False,
        )
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
            group = form.cleaned_data['group']
            target_user.groups.set([group])
            messages.success(
                request,
                f"Role updated: {target_user.username} → {group.name}",
            )
        else:
            messages.error(request, "Invalid role selection. Please try again.")

        return redirect('idan_muteruz:admin_panel')
