from django.contrib import messages
from django.contrib.auth import get_user_model, login
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.models import Group
from django.contrib.auth.views import LoginView, LogoutView, PasswordChangeView
from django.contrib.messages.views import SuccessMessageMixin
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

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['user_form'] = UserUpdateForm(
            instance=self.request.user,
            user=self.request.user,
        )
        context['profile_form'] = ProfileForm(instance=self.request.user.profile)
        return context

    def post(self, request, *args, **kwargs):
        user_form = UserUpdateForm(
            request.POST,
            instance=request.user,
            user=request.user,
        )
        profile_form = ProfileForm(request.POST, instance=request.user.profile)

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
    POST-only endpoint: replaces a target user's group membership with the
    single group chosen in the form.

    Only staff and superusers may call this view.
    Instructors can view the admin panel but cannot change roles.
    """

    login_url = reverse_lazy('idan_muteruz:login')
    http_method_names = ['post']

    def post(self, request, pk):
        target_user = get_object_or_404(User, pk=pk)
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
