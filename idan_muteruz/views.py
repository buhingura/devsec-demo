from django.contrib import messages
from django.contrib.auth import get_user_model, login
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.models import Group
from django.contrib.auth.views import (
    LoginView,
    LogoutView,
    PasswordChangeView,
    PasswordResetView as BasePasswordResetView,
    PasswordResetDoneView as BasePasswordResetDoneView,
    PasswordResetConfirmView as BasePasswordResetConfirmView,
    PasswordResetCompleteView as BasePasswordResetCompleteView,
)
from django.contrib.messages.views import SuccessMessageMixin
from django.core.exceptions import PermissionDenied
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse_lazy
from django.views.generic import FormView, RedirectView, TemplateView, View

from .forms import (
    AssignRoleForm,
    ProfileForm,
    RegistrationForm,
    CustomPasswordChangeForm,
    UserUpdateForm,
)
from .mixins import PrivilegedAccessMixin, StaffRequiredMixin

User = get_user_model()


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
    template_name = 'idan_muteruz/login.html'
    redirect_authenticated_user = True
    next_page = reverse_lazy('idan_muteruz:dashboard')


class UserLogoutView(LogoutView):
    next_page = reverse_lazy('idan_muteruz:login')
    http_method_names = ['get', 'post', 'head', 'options', 'trace']


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


# ---------------------------------------------------------------------------
# Password reset — 4-step flow
# ---------------------------------------------------------------------------

class UserPasswordResetView(BasePasswordResetView):
    """
    Step 1 — the user enters their email address.

    Security design:
    · Django's PasswordResetView only sends mail when the address belongs to
      an *active* user with a usable password.  We do not alter this behaviour.
    · success_url always points to the same "sent" page regardless of whether
      the address exists — this prevents account enumeration (an attacker
      cannot distinguish "email found" from "email not found").
    · Authenticated users are redirected to the dashboard; they should use
      the normal password-change flow (/password/change/) instead.
    · Tokens are produced by Django's PasswordResetTokenGenerator:
      HMAC-SHA256 over (user pk, password hash, last-login timestamp, current
      timestamp).  They are bound to the account state and expire after
      PASSWORD_RESET_TIMEOUT seconds (configured to 1 hour).
    """

    template_name        = 'idan_muteruz/password_reset_request.html'
    email_template_name  = 'idan_muteruz/email/password_reset_body.txt'
    subject_template_name = 'idan_muteruz/email/password_reset_subject.txt'
    success_url          = reverse_lazy('idan_muteruz:password_reset_sent')
    from_email           = None  # falls back to settings.DEFAULT_FROM_EMAIL

    def dispatch(self, request, *args, **kwargs):
        # Authenticated users already have a working account; redirect them to
        # the dashboard so they use the explicit password-change view instead.
        if request.user.is_authenticated:
            return redirect('idan_muteruz:dashboard')
        return super().dispatch(request, *args, **kwargs)


class UserPasswordResetSentView(BasePasswordResetDoneView):
    """
    Step 2 — always displayed after the form is submitted.

    Shown regardless of whether the submitted email belongs to a real account.
    The identical response for both cases is the primary anti-enumeration guard:
    an attacker cannot infer which email addresses are registered.
    """

    template_name = 'idan_muteruz/password_reset_sent.html'


class UserPasswordResetConfirmView(BasePasswordResetConfirmView):
    """
    Step 3 — validates the uidb64/token pair from the reset link and presents
    the new-password form if the link is valid.

    Security design:
    · Token validation (HMAC check + expiry) is handled entirely by Django.
    · Django stores the validated token in the session and redirects to a
      token-free URL (<uidb64>/set-password/), so the token never appears in
      the Referer header when the password form is submitted.
    · post_reset_login=False — the user must explicitly sign in after resetting.
      Auto-login after reset would let anyone who intercepts the email link
      silently gain a session without knowing the previous password.
    · Tokens are single-use: the generator checks the password hash, so the
      moment the password is saved the old token is implicitly invalidated.
    · Invalid or expired links surface a clear message via the template's
      `validlink` context flag — no stack traces or verbose errors.
    """

    template_name = 'idan_muteruz/password_reset_confirm.html'
    success_url   = reverse_lazy('idan_muteruz:password_reset_complete')
    post_reset_login = False  # require explicit login after reset


class UserPasswordResetCompleteView(BasePasswordResetCompleteView):
    """Step 4 — reset confirmed; displays a direct link to the sign-in page."""

    template_name = 'idan_muteruz/password_reset_complete.html'


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
