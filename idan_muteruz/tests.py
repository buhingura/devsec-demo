from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.test import TestCase
from django.urls import reverse

from .models import Profile

User = get_user_model()


class AuthenticationFlowTests(TestCase):
    def setUp(self):
        self.credentials = {
            'username': 'tester',
            'email': 'tester@example.com',
            'password': 'StrongP@ssword123',
        }
        self.user = User.objects.create_user(
            username=self.credentials['username'],
            email=self.credentials['email'],
            password=self.credentials['password'],
        )

    def test_successful_registration(self):
        response = self.client.post(
            reverse('idan_muteruz:register'),
            data={
                'username': 'newuser',
                'email': 'newuser@example.com',
                'first_name': 'New',
                'last_name': 'User',
                'password1': 'NewStrongP@ssword123',
                'password2': 'NewStrongP@ssword123',
            },
            follow=True,
        )

        self.assertRedirects(response, reverse('idan_muteruz:login'))
        self.assertTrue(User.objects.filter(username='newuser', email='newuser@example.com').exists())
        self.assertContains(response, 'Account created successfully. Please sign in.')

    def test_registration_failure_invalid_data(self):
        response = self.client.post(
            reverse('idan_muteruz:register'),
            data={
                'username': '',
                'email': 'invalid-email',
                'password1': 'short',
                'password2': 'short',
            },
        )

        self.assertEqual(response.status_code, 200)
        form = response.context['form']
        self.assertIn('username', form.errors)
        self.assertIn('email', form.errors)
        self.assertFalse(User.objects.filter(email='invalid-email').exists())

    def test_login_success_and_failure(self):
        login_url = reverse('idan_muteruz:login')

        response = self.client.post(
            login_url,
            data={'username': self.credentials['username'], 'password': self.credentials['password']},
            follow=True,
        )
        self.assertTrue(response.context['user'].is_authenticated)
        self.assertRedirects(response, reverse('idan_muteruz:dashboard'))

        self.client.logout()
        response = self.client.post(
            login_url,
            data={'username': self.credentials['username'], 'password': 'wrong-password'},
            follow=True,
        )
        self.assertContains(response, 'Please enter a correct username and password.')

    def test_logout_behavior(self):
        self.client.login(username=self.credentials['username'], password=self.credentials['password'])
        response = self.client.post(reverse('idan_muteruz:logout'), follow=True)

        self.assertRedirects(response, reverse('idan_muteruz:login'))
        self.assertFalse(response.context['user'].is_authenticated)

    def test_protected_routes_redirect_for_anonymous_user(self):
        dashboard_url = reverse('idan_muteruz:dashboard')
        profile_url = reverse('idan_muteruz:profile')

        response = self.client.get(dashboard_url)
        self.assertRedirects(response, f"{reverse('idan_muteruz:login')}?next={dashboard_url}")

        response = self.client.get(profile_url)
        self.assertRedirects(response, f"{reverse('idan_muteruz:login')}?next={profile_url}")

    def test_password_change_functionality(self):
        self.client.login(username=self.credentials['username'], password=self.credentials['password'])
        response = self.client.post(
            reverse('idan_muteruz:password_change'),
            data={
                'old_password': self.credentials['password'],
                'new_password1': 'UpdatedP@ssword789',
                'new_password2': 'UpdatedP@ssword789',
            },
            follow=True,
        )

        self.assertRedirects(response, reverse('idan_muteruz:profile'))
        self.assertContains(response, 'Your password has been changed successfully.')
        self.client.logout()
        self.assertTrue(self.client.login(username=self.credentials['username'], password='UpdatedP@ssword789'))


# ---------------------------------------------------------------------------
# RBAC Tests
# ---------------------------------------------------------------------------

class RBACTestBase(TestCase):
    """
    Shared fixtures for all RBAC test cases.

    Groups and the custom permission are created once per test class via
    setUpTestData(), which is far faster than per-test setUp().

    User roster:
        student     → in 'students' group, no special permissions
        instructor  → in 'instructors' group, has can_access_admin_panel
        staff_user  → is_staff=True (but no group), accesses admin panel via flag
        superuser   → is_superuser=True, unrestricted access
    """

    @classmethod
    def setUpTestData(cls):
        # --- Groups -----------------------------------------------------------
        cls.students_group = Group.objects.create(name='students')
        cls.instructors_group = Group.objects.create(name='instructors')
        cls.admins_group = Group.objects.create(name='admins')

        # --- Permission -------------------------------------------------------
        profile_ct = ContentType.objects.get_for_model(Profile)
        cls.admin_panel_perm, _ = Permission.objects.get_or_create(
            codename='can_access_admin_panel',
            content_type=profile_ct,
            defaults={'name': 'Can access the admin panel'},
        )
        cls.instructors_group.permissions.add(cls.admin_panel_perm)
        cls.admins_group.permissions.add(cls.admin_panel_perm)

        # --- Users ------------------------------------------------------------
        cls.student = User.objects.create_user(
            username='rbac_student',
            email='student@rbac.test',
            password='TestPass!1',
        )
        cls.student.groups.set([cls.students_group])

        cls.instructor = User.objects.create_user(
            username='rbac_instructor',
            email='instructor@rbac.test',
            password='TestPass!1',
        )
        cls.instructor.groups.set([cls.instructors_group])

        cls.staff_user = User.objects.create_user(
            username='rbac_staff',
            email='staff@rbac.test',
            password='TestPass!1',
            is_staff=True,
        )

        cls.superuser = User.objects.create_superuser(
            username='rbac_superuser',
            email='superuser@rbac.test',
            password='TestPass!1',
        )


class AnonymousAccessTests(RBACTestBase):
    """Anonymous users may only reach public (unauthenticated) pages."""

    def _assert_redirects_to_login(self, url: str) -> None:
        expected = f"{reverse('idan_muteruz:login')}?next={url}"
        response = self.client.get(url)
        self.assertRedirects(response, expected)

    def test_dashboard_redirects_to_login(self):
        self._assert_redirects_to_login(reverse('idan_muteruz:dashboard'))

    def test_profile_redirects_to_login(self):
        self._assert_redirects_to_login(reverse('idan_muteruz:profile'))

    def test_password_change_redirects_to_login(self):
        self._assert_redirects_to_login(reverse('idan_muteruz:password_change'))

    def test_admin_panel_redirects_to_login(self):
        self._assert_redirects_to_login(reverse('idan_muteruz:admin_panel'))

    def test_login_page_is_public(self):
        response = self.client.get(reverse('idan_muteruz:login'))
        self.assertEqual(response.status_code, 200)

    def test_register_page_is_public(self):
        response = self.client.get(reverse('idan_muteruz:register'))
        self.assertEqual(response.status_code, 200)


class AuthenticatedStudentAccessTests(RBACTestBase):
    """
    Authenticated students have access to user-level pages but are forbidden
    from privileged pages (HTTP 403, not a redirect to login).
    """

    def setUp(self):
        self.client.force_login(self.student)

    def test_can_access_dashboard(self):
        self.assertEqual(self.client.get(reverse('idan_muteruz:dashboard')).status_code, 200)

    def test_can_access_profile(self):
        self.assertEqual(self.client.get(reverse('idan_muteruz:profile')).status_code, 200)

    def test_can_access_password_change(self):
        self.assertEqual(self.client.get(reverse('idan_muteruz:password_change')).status_code, 200)

    def test_admin_panel_returns_403(self):
        """Authenticated student should get 403, not a redirect to login."""
        response = self.client.get(reverse('idan_muteruz:admin_panel'))
        self.assertEqual(response.status_code, 403)

    def test_admin_panel_direct_url_blocked(self):
        """Bypass URL name — hit the path directly; still 403."""
        response = self.client.get('/admin-panel/')
        self.assertEqual(response.status_code, 403)

    def test_student_does_not_have_admin_panel_permission(self):
        self.assertFalse(self.student.has_perm('idan_muteruz.can_access_admin_panel'))


class PrivilegedInstructorAccessTests(RBACTestBase):
    """
    Instructors hold can_access_admin_panel via their group and should be
    admitted to the admin panel.
    """

    def setUp(self):
        self.client.force_login(self.instructor)

    def test_can_access_dashboard(self):
        self.assertEqual(self.client.get(reverse('idan_muteruz:dashboard')).status_code, 200)

    def test_can_access_profile(self):
        self.assertEqual(self.client.get(reverse('idan_muteruz:profile')).status_code, 200)

    def test_can_access_admin_panel(self):
        self.assertEqual(self.client.get(reverse('idan_muteruz:admin_panel')).status_code, 200)

    def test_instructor_has_admin_panel_permission(self):
        # Reload from DB to ensure permission cache is fresh.
        instructor = User.objects.get(pk=self.instructor.pk)
        self.assertTrue(instructor.has_perm('idan_muteruz.can_access_admin_panel'))

    def test_instructor_is_not_staff(self):
        """Instructors are privileged via permission, not is_staff."""
        self.assertFalse(self.instructor.is_staff)


class PrivilegedStaffAccessTests(RBACTestBase):
    """Staff users (is_staff=True) should be admitted without a permission."""

    def setUp(self):
        self.client.force_login(self.staff_user)

    def test_can_access_dashboard(self):
        self.assertEqual(self.client.get(reverse('idan_muteruz:dashboard')).status_code, 200)

    def test_can_access_admin_panel(self):
        self.assertEqual(self.client.get(reverse('idan_muteruz:admin_panel')).status_code, 200)

    def test_staff_without_explicit_permission_admitted(self):
        """Staff access is granted via is_staff flag alone — no group needed."""
        self.assertFalse(
            self.staff_user.has_perm('idan_muteruz.can_access_admin_panel'),
            "Staff user should not need the explicit permission.",
        )
        response = self.client.get(reverse('idan_muteruz:admin_panel'))
        self.assertEqual(response.status_code, 200)


class SuperuserAccessTests(RBACTestBase):
    """Superusers bypass all permission checks."""

    def setUp(self):
        self.client.force_login(self.superuser)

    def test_can_access_all_views(self):
        urls = [
            reverse('idan_muteruz:dashboard'),
            reverse('idan_muteruz:profile'),
            reverse('idan_muteruz:password_change'),
            reverse('idan_muteruz:admin_panel'),
        ]
        for url in urls:
            with self.subTest(url=url):
                self.assertEqual(self.client.get(url).status_code, 200)


class GroupAssignmentTests(RBACTestBase):
    """Verify that group membership correctly grants / denies access."""

    def test_removing_instructor_from_group_revokes_access(self):
        """Removing instructor from instructors group should deny admin panel."""
        self.instructor.groups.clear()
        self.client.force_login(self.instructor)
        response = self.client.get(reverse('idan_muteruz:admin_panel'))
        self.assertEqual(response.status_code, 403)

    def test_adding_student_to_instructors_grants_access(self):
        """Promoting a student to instructors should grant admin panel access."""
        self.student.groups.add(self.instructors_group)
        self.client.force_login(self.student)
        response = self.client.get(reverse('idan_muteruz:admin_panel'))
        self.assertEqual(response.status_code, 200)
        # Cleanup — restore original state for other tests in this class.
        self.student.groups.set([self.students_group])


class AssignRoleViewTests(RBACTestBase):
    """
    Tests for the POST-only AssignRoleView endpoint.

    Security contract:
        - Anonymous             → redirect to login
        - Authenticated student → HTTP 403
        - Instructor            → HTTP 403 (can VIEW panel, cannot CHANGE roles)
        - Staff / Superuser     → allowed, group membership updated
    """

    def _assign_url(self, user_pk):
        return reverse('idan_muteruz:assign_role', kwargs={'pk': user_pk})

    # -- Access control -------------------------------------------------------

    def test_anonymous_redirected_to_login(self):
        url = self._assign_url(self.student.pk)
        response = self.client.post(url, data={f'user_{self.student.pk}-group': self.instructors_group.pk})
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse('idan_muteruz:login'), response['Location'])

    def test_student_cannot_assign_roles(self):
        self.client.force_login(self.student)
        response = self.client.post(
            self._assign_url(self.student.pk),
            data={f'user_{self.student.pk}-group': self.instructors_group.pk},
        )
        self.assertEqual(response.status_code, 403)

    def test_instructor_cannot_assign_roles(self):
        """Instructors can view the panel but not mutate roles."""
        self.client.force_login(self.instructor)
        response = self.client.post(
            self._assign_url(self.student.pk),
            data={f'user_{self.student.pk}-group': self.instructors_group.pk},
        )
        self.assertEqual(response.status_code, 403)

    # -- Staff assignment -----------------------------------------------------

    def test_staff_can_promote_student_to_instructor(self):
        self.client.force_login(self.staff_user)
        response = self.client.post(
            self._assign_url(self.student.pk),
            data={f'user_{self.student.pk}-group': self.instructors_group.pk},
            follow=True,
        )
        self.assertRedirects(response, reverse('idan_muteruz:admin_panel'))
        self.student.refresh_from_db()
        self.assertIn(self.instructors_group, self.student.groups.all())
        self.assertNotIn(self.students_group, self.student.groups.all())
        # Restore
        self.student.groups.set([self.students_group])

    def test_staff_can_demote_instructor_to_student(self):
        self.client.force_login(self.staff_user)
        response = self.client.post(
            self._assign_url(self.instructor.pk),
            data={f'user_{self.instructor.pk}-group': self.students_group.pk},
            follow=True,
        )
        self.assertRedirects(response, reverse('idan_muteruz:admin_panel'))
        self.instructor.refresh_from_db()
        self.assertIn(self.students_group, self.instructor.groups.all())
        self.assertNotIn(self.instructors_group, self.instructor.groups.all())
        # Restore
        self.instructor.groups.set([self.instructors_group])

    def test_superuser_can_assign_any_role(self):
        self.client.force_login(self.superuser)
        response = self.client.post(
            self._assign_url(self.student.pk),
            data={f'user_{self.student.pk}-group': self.admins_group.pk},
            follow=True,
        )
        self.assertRedirects(response, reverse('idan_muteruz:admin_panel'))
        self.student.refresh_from_db()
        self.assertIn(self.admins_group, self.student.groups.all())
        # Restore
        self.student.groups.set([self.students_group])

    def test_assign_role_replaces_all_existing_groups(self):
        """set() should replace, not append."""
        # Give student both groups first
        self.student.groups.set([self.students_group, self.instructors_group])
        self.client.force_login(self.staff_user)
        self.client.post(
            self._assign_url(self.student.pk),
            data={f'user_{self.student.pk}-group': self.students_group.pk},
        )
        self.student.refresh_from_db()
        self.assertEqual(list(self.student.groups.all()), [self.students_group])

    def test_invalid_form_shows_error_message(self):
        """Submitting a nonexistent group pk should not crash — shows error."""
        self.client.force_login(self.staff_user)
        response = self.client.post(
            self._assign_url(self.student.pk),
            data={f'user_{self.student.pk}-group': 99999},  # does not exist
            follow=True,
        )
        self.assertRedirects(response, reverse('idan_muteruz:admin_panel'))
        messages_list = list(response.context['messages'])
        self.assertTrue(any('Invalid' in str(m) for m in messages_list))

    # -- UI presence ----------------------------------------------------------

    def test_admin_panel_shows_user_management_table_for_staff(self):
        self.client.force_login(self.staff_user)
        response = self.client.get(reverse('idan_muteruz:admin_panel'))
        self.assertEqual(response.status_code, 200)
        self.assertIn('user_rows', response.context)
        self.assertGreater(len(response.context['user_rows']), 0)

    def test_admin_panel_hides_user_management_table_for_instructor(self):
        """Instructors should NOT see the User Management section."""
        self.client.force_login(self.instructor)
        response = self.client.get(reverse('idan_muteruz:admin_panel'))
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('user_rows', response.context)
