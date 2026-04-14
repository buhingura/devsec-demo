from django.contrib import admin
from django.contrib.auth import get_user_model
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.models import Group
from django.utils.html import format_html

from .models import Profile


User = get_user_model()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _role_label(user) -> str:
    """Return a human-readable role string for a User instance."""
    if user.is_superuser:
        return "Superuser"
    if user.is_staff:
        return "Staff"
    groups = list(user.groups.values_list("name", flat=True))
    return ", ".join(g.capitalize() for g in groups) if groups else "—"


# ---------------------------------------------------------------------------
# Profile Admin
# ---------------------------------------------------------------------------

@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    list_display  = ("user", "display_name", "get_role", "created_at", "updated_at")
    search_fields = ("user__username", "user__email", "display_name")
    readonly_fields = ("created_at", "updated_at")
    list_filter   = ("user__groups", "user__is_staff", "user__is_superuser")

    @admin.display(description="Role")
    def get_role(self, obj):
        label = _role_label(obj.user)
        colours = {
            "Superuser": ("#4338CA", "#EEF2FF"),
            "Staff":     ("#4338CA", "#EEF2FF"),
            "—":         ("#6B7280", "#F3F4F6"),
        }
        bg, fg = colours.get(label, ("#065F46", "#ECFDF5"))
        return format_html(
            '<span style="background:{};color:{};padding:.2rem .6rem;'
            'border-radius:999px;font-size:.75rem;font-weight:600;">{}</span>',
            bg, fg, label,
        )


# ---------------------------------------------------------------------------
# Custom User Admin  (unregister default, register ours)
# ---------------------------------------------------------------------------

admin.site.unregister(User)


class RoleAssignmentFilter(admin.SimpleListFilter):
    """Sidebar filter: filter users by their RBAC group."""

    title = "Role"
    parameter_name = "role"

    def lookups(self, request, model_admin):
        choices = [
            ("superuser",  "Superuser"),
            ("staff",      "Staff"),
            ("no_group",   "No group"),
        ]
        for g in Group.objects.order_by("name"):
            choices.append((f"group__{g.name}", g.name.capitalize()))
        return choices

    def queryset(self, request, queryset):
        v = self.value()
        if v == "superuser":
            return queryset.filter(is_superuser=True)
        if v == "staff":
            return queryset.filter(is_staff=True, is_superuser=False)
        if v == "no_group":
            return queryset.filter(groups__isnull=True, is_staff=False, is_superuser=False)
        if v and v.startswith("group__"):
            return queryset.filter(groups__name=v[len("group__"):])
        return queryset


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display  = ("username", "email", "get_full_name", "get_role", "is_active")
    list_filter   = (RoleAssignmentFilter, "is_active")
    search_fields = ("username", "email", "first_name", "last_name")
    actions       = ["make_student", "make_instructor", "make_admin_group"]

    # Put group assignment at the very top of the change form
    fieldsets = (
        (None, {"fields": ("username", "password")}),
        ("Role / Groups", {
            "fields": ("groups",),
            "description": (
                "Assign exactly one group to set the user's role. "
                "Staff and superuser flags grant additional Django admin access."
            ),
        }),
        ("Personal info", {"fields": ("first_name", "last_name", "email")}),
        ("Permissions",   {"fields": ("is_active", "is_staff", "is_superuser", "user_permissions")}),
        ("Dates",         {"fields": ("last_login", "date_joined"), "classes": ("collapse",)}),
    )

    filter_horizontal = ("groups", "user_permissions")

    # ------------------------------------------------------------------
    # Display helpers
    # ------------------------------------------------------------------

    @admin.display(description="Role")
    def get_role(self, obj):
        label = _role_label(obj)
        colours = {
            "Superuser": ("#4338CA", "#EEF2FF"),
            "Staff":     ("#4338CA", "#EEF2FF"),
            "—":         ("#6B7280", "#F3F4F6"),
        }
        bg, fg = colours.get(label, ("#065F46", "#ECFDF5"))
        return format_html(
            '<span style="background:{};color:{};padding:.2rem .6rem;'
            'border-radius:999px;font-size:.75rem;font-weight:600;">{}</span>',
            bg, fg, label,
        )

    # ------------------------------------------------------------------
    # Bulk-action: assign role
    # ------------------------------------------------------------------

    def _bulk_assign_group(self, request, queryset, group_name: str):
        try:
            group = Group.objects.get(name=group_name)
        except Group.DoesNotExist:
            self.message_user(
                request,
                f'Group "{group_name}" does not exist. Run: python manage.py setup_groups',
                level="error",
            )
            return
        count = 0
        for user in queryset.filter(is_superuser=False):
            user.groups.set([group])
            count += 1
        self.message_user(request, f'{count} user(s) assigned to "{group_name}".')

    @admin.action(description="Assign role → Student")
    def make_student(self, request, queryset):
        self._bulk_assign_group(request, queryset, "students")

    @admin.action(description="Assign role → Instructor")
    def make_instructor(self, request, queryset):
        self._bulk_assign_group(request, queryset, "instructors")

    @admin.action(description="Assign role → Admin group")
    def make_admin_group(self, request, queryset):
        self._bulk_assign_group(request, queryset, "admins")
