"""
RBAC Mixins
===========
Reusable class-based view mixins for role-based access control.

All mixins build on Django's UserPassesTestMixin, which already handles the
"redirect unauthenticated users to login / raise 403 for authenticated
users that fail the test" split correctly (see AccessMixin.handle_no_permission).

Roles:
    Anonymous      → public pages only (login, register)
    Authenticated  → user-level pages (dashboard, profile, password change)
    Privileged     → restricted pages (admin panel)
                     granted via:  is_staff | is_superuser
                                 | idan_muteruz.can_access_admin_panel permission
"""

from django.contrib.auth.mixins import UserPassesTestMixin


class StaffRequiredMixin(UserPassesTestMixin):
    """
    Allow access only to staff (is_staff=True) and superusers.

    Unauthenticated users    → redirect to login
    Authenticated non-staff  → HTTP 403 Forbidden
    """

    def test_func(self) -> bool:
        user = self.request.user
        return user.is_staff or user.is_superuser


class PrivilegedAccessMixin(UserPassesTestMixin):
    """
    Allow access to staff, superusers, or users that hold a named permission.

    Set ``permission_required`` on the view class (dotted ``app_label.codename``
    string) to gate access by a Django permission in addition to is_staff.

    Unauthenticated users              → redirect to login
    Authenticated, insufficient access → HTTP 403 Forbidden
    """

    permission_required: str | None = None

    def test_func(self) -> bool:
        user = self.request.user
        if user.is_superuser or user.is_staff:
            return True
        if self.permission_required:
            return user.has_perm(self.permission_required)
        return False


class GroupRequiredMixin(UserPassesTestMixin):
    """
    Allow access only to users belonging to at least one of the listed groups.

    Set ``required_groups = ['group_name', ...]`` on the view class.
    Superusers bypass the group check entirely.

    Unauthenticated users                    → redirect to login
    Authenticated, not in required group(s)  → HTTP 403 Forbidden
    """

    required_groups: list[str] = []

    def test_func(self) -> bool:
        user = self.request.user
        if user.is_superuser:
            return True
        if not self.required_groups:
            return False
        return user.groups.filter(name__in=self.required_groups).exists()
