"""
Management command: setup_groups
================================
Creates the three application roles as Django Groups and assigns the
``can_access_admin_panel`` permission to the privileged groups.

Roles
-----
    students     Default role for every newly registered user.
                 No extra permissions beyond authenticated access.

    instructors  Privileged role.
                 Granted: idan_muteruz.can_access_admin_panel

    admins       Privileged role (typically also set is_staff=True via
                 Django admin).
                 Granted: idan_muteruz.can_access_admin_panel

Usage
-----
    python manage.py setup_groups

Run this once after migrations, then again whenever you add new permissions.
It is idempotent — safe to run multiple times.
"""

from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.core.management.base import BaseCommand

from idan_muteruz.models import Profile


class Command(BaseCommand):
    help = "Create default RBAC groups and assign permissions."

    # Map group-name → list of (app_label, codename) permissions to assign.
    GROUP_PERMISSIONS: dict[str, list[tuple[str, str]]] = {
        "students": [],
        "instructors": [("idan_muteruz", "can_access_admin_panel")],
        "admins": [("idan_muteruz", "can_access_admin_panel")],
    }

    def handle(self, *args, **options) -> None:
        profile_ct = ContentType.objects.get_for_model(Profile)
        created_count = 0
        updated_count = 0

        for group_name, perm_specs in self.GROUP_PERMISSIONS.items():
            group, created = Group.objects.get_or_create(name=group_name)
            if created:
                created_count += 1
                self.stdout.write(f"  Created group  : {group_name}")
            else:
                updated_count += 1
                self.stdout.write(f"  Found group    : {group_name}")

            for app_label, codename in perm_specs:
                try:
                    perm = Permission.objects.get(
                        content_type__app_label=app_label,
                        codename=codename,
                    )
                    group.permissions.add(perm)
                    self.stdout.write(
                        f"    + permission  : {app_label}.{codename}"
                    )
                except Permission.DoesNotExist:
                    self.stderr.write(
                        self.style.WARNING(
                            f"    ! Permission '{app_label}.{codename}' not found. "
                            "Run migrations first."
                        )
                    )

        self.stdout.write(
            self.style.SUCCESS(
                f"\nDone — {created_count} group(s) created, "
                f"{updated_count} group(s) already existed."
            )
        )
        self.stdout.write(
            "\nTo assign a user to a group via the shell:\n"
            "  from django.contrib.auth.models import Group, User\n"
            "  user = User.objects.get(username='alice')\n"
            "  user.groups.set([Group.objects.get(name='instructors')])\n"
        )
