from datetime import timedelta

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from .models import LoginAttempt, Profile

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


# ---------------------------------------------------------------------------
# IDOR Tests
# ---------------------------------------------------------------------------

class IDORTests(RBACTestBase):
    """
    Tests verifying that Insecure Direct Object Reference (IDOR) attacks are
    not possible in any view that handles user-owned resources.

    Audit summary
    -------------
    ProfileView              /profile/
        No identifier in URL.  Always bound to request.user and
        request.user.profile.  Structurally immune to IDOR.

    UserPasswordChangeView   /password/change/
        No identifier in URL.  Django's PasswordChangeView always sets
        form.user = request.user.  Structurally immune to IDOR.

    DashboardView            /dashboard/
        Read-only.  No identifier.  Not vulnerable.

    AssignRoleView           /admin-panel/users/<pk>/assign-role/
        IDOR vulnerability fixed: object-level checks now prevent:
          • targeting a superuser's pk
          • a staff user modifying another staff user's groups
          • any actor reassigning their own groups (self-escalation)
    """

    # ── ProfileView — structurally immune (no pk in URL) ─────────────────────

    def test_profile_view_always_shows_own_data(self):
        """GET /profile/ returns the authenticated user's own form instances."""
        self.client.force_login(self.student)
        response = self.client.get(reverse('idan_muteruz:profile'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['user_form'].instance, self.student)
        self.assertEqual(
            response.context['profile_form'].instance,
            self.student.profile,
        )

    def test_profile_post_never_modifies_another_users_data(self):
        """
        A POST to /profile/ must only ever update the authenticated user's
        own record.  The instructor's data must be untouched.
        """
        original_email = self.instructor.email
        original_bio   = self.instructor.profile.bio

        self.client.force_login(self.student)
        self.client.post(
            reverse('idan_muteruz:profile'),
            data={
                'first_name':   'Hacker',
                'last_name':    'Attempt',
                'email':        self.student.email,
                'display_name': 'pwned',
                'bio':          'injected',
            },
        )

        self.instructor.refresh_from_db()
        self.instructor.profile.refresh_from_db()
        self.assertEqual(self.instructor.email,        original_email)
        self.assertEqual(self.instructor.profile.bio,  original_bio)

    def test_profile_anonymous_redirected_to_login(self):
        url = reverse('idan_muteruz:profile')
        response = self.client.get(url)
        self.assertRedirects(response, f"{reverse('idan_muteruz:login')}?next={url}")

    # ── UserPasswordChangeView — structurally immune (no pk in URL) ──────────

    def test_password_change_form_is_bound_to_authenticated_user(self):
        """The change-password form must be bound to the logged-in user only."""
        self.client.force_login(self.student)
        response = self.client.get(reverse('idan_muteruz:password_change'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['form'].user, self.student)

    def test_password_change_anonymous_redirected_to_login(self):
        url = reverse('idan_muteruz:password_change')
        response = self.client.get(url)
        self.assertRedirects(response, f"{reverse('idan_muteruz:login')}?next={url}")

    # ── AssignRoleView — object-level authorization on <pk> ──────────────────

    def _post_assign(self, actor, target_pk, group=None):
        """Helper: POST assign-role as actor, targeting target_pk."""
        self.client.force_login(actor)
        group_pk = (group or self.students_group).pk
        return self.client.post(
            reverse('idan_muteruz:assign_role', kwargs={'pk': target_pk}),
            data={f'user_{target_pk}-group': group_pk},
        )

    def test_cannot_target_superuser_pk(self):
        """
        IDOR fix check 1: staff must not be able to modify a superuser's groups
        by guessing their pk.
        """
        # Capture the group set BEFORE the attempt so we can compare after.
        groups_before = set(self.superuser.groups.values_list('pk', flat=True))
        response = self._post_assign(self.staff_user, self.superuser.pk)
        self.assertEqual(response.status_code, 403)
        # Superuser's groups must be completely unchanged.
        groups_after = set(self.superuser.groups.values_list('pk', flat=True))
        self.assertEqual(groups_before, groups_after)

    def test_superuser_cannot_target_another_superuser_pk(self):
        """Even superusers cannot modify another superuser via this endpoint."""
        another_super = User.objects.create_superuser(
            username='super2', password='S3cure!pass', email='super2@idor.test',
        )
        response = self._post_assign(self.superuser, another_super.pk)
        self.assertEqual(response.status_code, 403)

    def test_staff_cannot_target_another_staff_user_pk(self):
        """
        IDOR fix check 2: a staff user must not be able to escalate or
        de-escalate a peer staff member by guessing their pk.
        """
        peer_staff = User.objects.create_user(
            username='peer_staff', password='S3cure!pass',
            email='peer@idor.test', is_staff=True,
        )
        response = self._post_assign(self.staff_user, peer_staff.pk)
        self.assertEqual(response.status_code, 403)

    def test_staff_cannot_reassign_own_pk(self):
        """
        IDOR fix check 3: a staff user must not be able to self-escalate by
        posting their own pk as the target.
        """
        response = self._post_assign(self.staff_user, self.staff_user.pk)
        self.assertEqual(response.status_code, 403)

    def test_superuser_cannot_reassign_own_pk(self):
        """Superusers are also blocked from self-assignment (check 1 applies)."""
        response = self._post_assign(self.superuser, self.superuser.pk)
        self.assertEqual(response.status_code, 403)

    def test_nonexistent_pk_returns_404_not_403(self):
        """
        A fabricated pk that matches no user must return 404, not 403.
        This avoids leaking whether a higher-privileged user with that pk
        exists; it simply says 'no such resource'.
        """
        self.client.force_login(self.staff_user)
        response = self.client.post(
            reverse('idan_muteruz:assign_role', kwargs={'pk': 999999}),
            data={'user_999999-group': self.students_group.pk},
        )
        self.assertEqual(response.status_code, 404)

    def test_staff_can_target_regular_user_pk(self):
        """Confirm the fix does not break legitimate staff assignment."""
        response = self._post_assign(
            self.staff_user, self.student.pk, group=self.instructors_group,
        )
        self.assertRedirects(
            response, reverse('idan_muteruz:admin_panel'),
            fetch_redirect_response=False,
        )
        self.student.refresh_from_db()
        self.assertIn(self.instructors_group, self.student.groups.all())
        # Restore
        self.student.groups.set([self.students_group])

    def test_superuser_can_target_staff_user_pk(self):
        """Only superusers may change a staff member's group (check 2 allows this)."""
        response = self._post_assign(
            self.superuser, self.staff_user.pk, group=self.admins_group,
        )
        self.assertRedirects(
            response, reverse('idan_muteruz:admin_panel'),
            fetch_redirect_response=False,
        )
        self.staff_user.refresh_from_db()
        self.assertIn(self.admins_group, self.staff_user.groups.all())
        # Restore
        self.staff_user.groups.clear()


# =============================================================================
# Brute-force / login-throttling tests
# =============================================================================

LOGIN_URL = '/idan_muteruz/login/'

# Use tight settings so tests run fast and are easy to reason about.
THROTTLE_SETTINGS = dict(
    LOGIN_MAX_ATTEMPTS=3,
    LOGIN_LOCKOUT_SECONDS=60,   # 1-minute window for tests
)


@override_settings(**THROTTLE_SETTINGS)
class BruteForceProtectionTests(TestCase):
    """
    Verify that the brute-force protection layer in UserLoginView behaves
    correctly under normal use and under abuse.

    Settings override:
        LOGIN_MAX_ATTEMPTS = 3
        LOGIN_LOCKOUT_SECONDS = 60 (1-minute sliding window)
    """

    def setUp(self):
        self.url = reverse('idan_muteruz:login')
        self.username = 'victim'
        self.password = 'CorrectP@ss999'
        self.user = User.objects.create_user(
            username=self.username,
            email='victim@example.com',
            password=self.password,
        )

    # ── helpers ───────────────────────────────────────────────────────────────

    def _post_login(self, username=None, password=None, **kwargs):
        return self.client.post(self.url, {
            'username': username or self.username,
            'password': password or self.password,
        }, **kwargs)

    def _fail_n_times(self, n, username=None):
        for _ in range(n):
            self._post_login(username=username or self.username, password='wrong')

    # ── normal-use tests ──────────────────────────────────────────────────────

    def test_correct_credentials_log_user_in(self):
        """Happy path: correct credentials redirect to dashboard."""
        response = self._post_login()
        self.assertRedirects(
            response,
            reverse('idan_muteruz:dashboard'),
            fetch_redirect_response=False,
        )

    def test_correct_credentials_record_success(self):
        """Successful login creates a LoginAttempt row with succeeded=True."""
        self._post_login()
        self.assertTrue(
            LoginAttempt.objects.filter(
                username__iexact=self.username, succeeded=True
            ).exists()
        )

    def test_wrong_password_shows_form_again(self):
        """A single wrong password stays on the login page (HTTP 200)."""
        response = self._post_login(password='wrong')
        self.assertEqual(response.status_code, 200)

    def test_failed_login_records_attempt(self):
        """Each failed attempt creates one LoginAttempt row with succeeded=False."""
        self._fail_n_times(2)
        self.assertEqual(
            LoginAttempt.objects.filter(
                username__iexact=self.username, succeeded=False
            ).count(),
            2,
        )

    def test_failed_login_below_threshold_is_not_locked(self):
        """One attempt below the limit does not trigger lockout."""
        self._fail_n_times(2)   # max = 3; still one below
        response = self._post_login()
        self.assertRedirects(
            response,
            reverse('idan_muteruz:dashboard'),
            fetch_redirect_response=False,
        )

    # ── lockout tests ─────────────────────────────────────────────────────────

    def test_lockout_after_max_failures(self):
        """After LOGIN_MAX_ATTEMPTS failures the next attempt is redirected."""
        self._fail_n_times(3)
        response = self._post_login()
        self.assertRedirects(
            response,
            self.url,
            fetch_redirect_response=False,
        )

    def test_lockout_message_shown_to_user(self):
        """The lockout redirect carries a flash error message."""
        self._fail_n_times(3)
        response = self._post_login(follow=True)
        messages_list = list(response.context['messages'])
        self.assertTrue(
            any('Too many failed sign-in attempts' in str(m) for m in messages_list),
            'Expected lockout message not found in response',
        )

    def test_lockout_message_includes_wait_time(self):
        """The lockout message tells the user how many minutes to wait."""
        self._fail_n_times(3)
        response = self._post_login(follow=True)
        messages_list = list(response.context['messages'])
        text = ' '.join(str(m) for m in messages_list)
        self.assertIn('minute', text)

    def test_correct_password_during_lockout_is_still_rejected(self):
        """
        Even with the correct password, a locked account must be rejected.
        This is the critical property: locking must happen before auth.
        """
        self._fail_n_times(3)
        response = self._post_login(password=self.password)
        self.assertRedirects(
            response,
            self.url,
            fetch_redirect_response=False,
        )
        # User must NOT be logged in
        self.assertNotIn('_auth_user_id', self.client.session)

    def test_lockout_does_not_add_extra_failure_record(self):
        """
        A request rejected by the lockout guard should not record an
        additional LoginAttempt row (the lock check fires before the form).
        """
        self._fail_n_times(3)
        count_before = LoginAttempt.objects.filter(
            username__iexact=self.username, succeeded=False
        ).count()
        self._post_login(password=self.password)   # locked — never reaches auth
        count_after = LoginAttempt.objects.filter(
            username__iexact=self.username, succeeded=False
        ).count()
        self.assertEqual(count_before, count_after)

    def test_lockout_is_per_account_not_global(self):
        """
        Failures on one account must not affect a different account.
        """
        other = User.objects.create_user(
            username='other', password='OtherP@ss999'
        )
        self._fail_n_times(3, username=self.username)
        # 'other' should still be able to log in normally
        response = self.client.post(self.url, {
            'username': 'other',
            'password': 'OtherP@ss999',
        })
        self.assertRedirects(
            response,
            reverse('idan_muteruz:dashboard'),
            fetch_redirect_response=False,
        )

    # ── window / expiry tests ─────────────────────────────────────────────────

    def test_old_failures_outside_window_do_not_count(self):
        """
        Failures older than LOGIN_LOCKOUT_SECONDS fall outside the window
        and must not contribute to the lockout counter.
        """
        # Create 3 failure rows, then back-date them outside the window.
        # (auto_now_add=True ignores values in create(), so we use update().)
        for _ in range(3):
            LoginAttempt.objects.create(username=self.username, succeeded=False)
        LoginAttempt.objects.filter(
            username__iexact=self.username, succeeded=False
        ).update(timestamp=timezone.now() - timedelta(seconds=61))

        # Those 3 old failures should NOT trigger lockout
        response = self._post_login()
        self.assertRedirects(
            response,
            reverse('idan_muteruz:dashboard'),
            fetch_redirect_response=False,
        )

    def test_unlock_after_window_expires(self):
        """
        After the lockout window passes, the account becomes accessible again.
        Simulated by back-dating all existing failure records.
        """
        self._fail_n_times(3)
        # Back-date all failure records to be outside the window
        LoginAttempt.objects.filter(
            username__iexact=self.username, succeeded=False
        ).update(timestamp=timezone.now() - timedelta(seconds=61))

        response = self._post_login()
        self.assertRedirects(
            response,
            reverse('idan_muteruz:dashboard'),
            fetch_redirect_response=False,
        )

    # ── counter-reset tests ───────────────────────────────────────────────────

    def test_successful_login_clears_failure_records(self):
        """
        A successful login deletes previous failure rows for that username,
        so the counter starts fresh on the next session.
        """
        self._fail_n_times(2)
        self.assertEqual(
            LoginAttempt.objects.filter(
                username__iexact=self.username, succeeded=False
            ).count(),
            2,
        )
        self._post_login(password=self.password)
        self.assertEqual(
            LoginAttempt.objects.filter(
                username__iexact=self.username, succeeded=False
            ).count(),
            0,
            'Failure records should have been cleared on successful login',
        )

    def test_after_successful_login_fresh_failures_count_again(self):
        """
        After logging in (which resets the counter), subsequent failures must
        accumulate and eventually trigger a lockout again.
        """
        # Fail twice, succeed once (clears failures), fail 3 more times
        self._fail_n_times(2)
        self._post_login(password=self.password)
        self.client.logout()
        self._fail_n_times(3)
        # Now the counter is back at max — should be locked
        response = self._post_login()
        self.assertRedirects(
            response,
            self.url,
            fetch_redirect_response=False,
        )


# =============================================================================
# CSRF protection tests
# =============================================================================

class CsrfProtectionTests(TestCase):
    """
    Verify that every state-changing endpoint enforces CSRF token validation
    and that the logout view rejects unsafe HTTP methods.

    All tests that check token rejection use ``Client(enforce_csrf_checks=True)``
    so Django's CSRF middleware actually validates tokens, exactly as it does
    in production.  The default test client disables CSRF checking; these tests
    explicitly opt back in.

    Audit summary (branch: assignment/fix-csrf-protection)
    -------------------------------------------------------
    Clean (no changes required):
    * All six POST forms include ``{% csrf_token %}``.
    * ``CsrfViewMiddleware`` is listed in MIDDLEWARE.
    * No ``@csrf_exempt`` decorator is used anywhere.
    * No AJAX requests exist in the codebase.

    Fixed:
    * ``UserLogoutView.http_method_names`` previously included ``'get'``,
      ``'head'``, and ``'trace'``.  While Django 5.2 has no ``get()``
      handler on LogoutView (so GET returned 405 in practice), the
      explicit inclusion was misleading, violated the principle that only
      POST may trigger a session-ending state change, and enabling TRACE
      creates a Cross-Site Tracing (XST) attack surface.
      Fixed: restricted to ``['post', 'options']``.
    """

    def setUp(self):
        self.csrf_client = Client(enforce_csrf_checks=True)
        self.password = 'StrongP@ss123'
        self.user = User.objects.create_user(
            username='csrftest',
            email='csrf@example.com',
            password=self.password,
        )
        self.staff = User.objects.create_user(
            username='staffcsrf',
            email='staff@example.com',
            password=self.password,
            is_staff=True,
        )
        self.target = User.objects.create_user(
            username='targetcsrf',
            email='target@example.com',
            password=self.password,
        )

    # ── helpers ───────────────────────────────────────────────────────────────

    def _login_csrf_client(self, user):
        """Log in via force_login and copy the session cookie to the
        CSRF-enforcing client so it can make authenticated requests."""
        self.client.force_login(user)
        session_cookie = self.client.cookies.get('sessionid')
        if session_cookie:
            self.csrf_client.cookies['sessionid'] = session_cookie.value

    # ── login endpoint ────────────────────────────────────────────────────────

    def test_login_post_without_csrf_token_returns_403(self):
        """POST to the login form without a CSRF token must be rejected."""
        response = self.csrf_client.post(
            reverse('idan_muteruz:login'),
            {'username': self.user.username, 'password': self.password},
        )
        self.assertEqual(response.status_code, 403)

    # ── register endpoint ─────────────────────────────────────────────────────

    def test_register_post_without_csrf_token_returns_403(self):
        """POST to the registration form without a CSRF token must be rejected."""
        response = self.csrf_client.post(
            reverse('idan_muteruz:register'),
            {
                'username': 'newcsrfuser',
                'email': 'new@example.com',
                'password1': self.password,
                'password2': self.password,
            },
        )
        self.assertEqual(response.status_code, 403)

    # ── profile endpoint ──────────────────────────────────────────────────────

    def test_profile_post_without_csrf_token_returns_403(self):
        """POST to the profile update form without a CSRF token must be rejected."""
        self._login_csrf_client(self.user)
        response = self.csrf_client.post(
            reverse('idan_muteruz:profile'),
            {'display_name': 'Attacker', 'bio': ''},
        )
        self.assertEqual(response.status_code, 403)

    # ── password change endpoint ──────────────────────────────────────────────

    def test_password_change_post_without_csrf_token_returns_403(self):
        """POST to the password-change form without a CSRF token must be rejected."""
        self._login_csrf_client(self.user)
        response = self.csrf_client.post(
            reverse('idan_muteruz:password_change'),
            {
                'old_password': self.password,
                'new_password1': 'NewP@ss99999',
                'new_password2': 'NewP@ss99999',
            },
        )
        self.assertEqual(response.status_code, 403)

    # ── logout endpoint ───────────────────────────────────────────────────────

    def test_logout_post_without_csrf_token_returns_403(self):
        """POST to the logout endpoint without a CSRF token must be rejected."""
        self._login_csrf_client(self.user)
        response = self.csrf_client.post(reverse('idan_muteruz:logout'))
        self.assertEqual(response.status_code, 403)

    def test_logout_get_returns_405(self):
        """
        GET requests to the logout URL must be rejected with 405.

        GET-based logout is a classic CSRF-via-safe-method vector: a malicious
        page embeds ``<img src='/logout/'>`` and the victim's browser silently
        fetches it.  Restricting to POST means a CSRF token is always required.

        This is the primary fix in this assignment: UserLogoutView previously
        listed 'get' in http_method_names.
        """
        self.client.force_login(self.user)
        response = self.client.get(reverse('idan_muteruz:logout'))
        self.assertEqual(response.status_code, 405)

    def test_logout_trace_returns_405(self):
        """
        TRACE requests to the logout URL must be rejected with 405.

        HTTP TRACE echoes request headers (including cookies) back to the
        caller.  In certain proxy configurations this enables Cross-Site
        Tracing (XST).  TRACE must never be permitted on an endpoint that
        manages authentication state.
        """
        self.client.force_login(self.user)
        response = self.client.generic('TRACE', reverse('idan_muteruz:logout'))
        self.assertEqual(response.status_code, 405)

    def test_logout_head_returns_405(self):
        """
        HEAD requests to the logout URL must return 405.

        HEAD is semantically read-only and must not trigger session destruction.
        """
        self.client.force_login(self.user)
        response = self.client.head(reverse('idan_muteruz:logout'))
        self.assertEqual(response.status_code, 405)

    # ── assign-role endpoint ──────────────────────────────────────────────────

    def test_assign_role_post_without_csrf_token_returns_403(self):
        """POST to the assign-role endpoint without a CSRF token must be rejected."""
        self._login_csrf_client(self.staff)
        students_group, _ = Group.objects.get_or_create(name='students')
        response = self.csrf_client.post(
            reverse('idan_muteruz:assign_role', kwargs={'pk': self.target.pk}),
            {f'user_{self.target.pk}-group': students_group.pk},
        )
        self.assertEqual(response.status_code, 403)

    # ── safe GET endpoints are unaffected by CSRF enforcement ─────────────────

    def test_login_get_is_accessible_without_token(self):
        """Safe GET requests must work normally; CSRF only covers state changes."""
        response = self.csrf_client.get(reverse('idan_muteruz:login'))
        self.assertEqual(response.status_code, 200)

    def test_register_get_is_accessible_without_token(self):
        """GET to the registration page must work normally."""
        response = self.csrf_client.get(reverse('idan_muteruz:register'))
        self.assertEqual(response.status_code, 200)


# =============================================================================
# Open-redirect tests
# =============================================================================

class OpenRedirectTests(TestCase):
    """
    Prove that every redirect target accepted by an auth-flow view is
    validated with ``url_has_allowed_host_and_scheme`` before use.

    Audit summary (branch: assignment/fix-open-redirects)
    -----------------------------------------------------
    Issue 1 — Template gap (login.html, register.html):
        Neither template included ``<input type="hidden" name="next" …>``.
        Django's ``RedirectURLMixin`` reads ``next`` from POST *first*, then
        falls back to GET.  Without the hidden field the value depended on
        the query string being preserved through the form POST — which is
        normally true but not guaranteed across all proxy/browser
        configurations.  Fixed: both templates now include the hidden field
        with the pre-validated value from the view's context.

    Issue 2 — RegisterView lacked next handling:
        ``RegisterView`` hardcoded ``success_url = reverse_lazy('…:login')``.
        Users arriving at ``/register/?next=/profile/`` were silently sent to
        plain ``/login/`` with no onward destination.  Worse, adding ``next``
        support naively — ``request.GET.get('next')`` without validation —
        would have been an open redirect.  Fixed: ``get_success_url()`` now
        calls ``_safe_next_url()`` and only appends a validated same-host URL
        to the login redirect.

    Issue 3 — Lockout redirect lost the next parameter:
        ``UserLoginView.post()`` did ``return redirect('idan_muteruz:login')``
        on lockout, silently discarding a valid ``next`` URL the user already
        held.  Fixed: the lockout handler now calls ``_safe_next_url()`` and
        appends the validated value to the login URL.

    Not an issue:
        ``UserLoginView`` and ``UserLogoutView`` inherit
        ``RedirectURLMixin.get_redirect_url()``, which calls
        ``url_has_allowed_host_and_scheme`` on every ``next`` parameter.
        No additional override is required; the protection is structural.
    """

    def setUp(self):
        self.password = 'StrongP@ss123'
        self.user = User.objects.create_user(
            username='redirecttest',
            email='redirect@example.com',
            password=self.password,
        )
        self.login_url = reverse('idan_muteruz:login')
        self.register_url = reverse('idan_muteruz:register')
        self.logout_url = reverse('idan_muteruz:logout')
        self.dashboard_url = reverse('idan_muteruz:dashboard')
        self.profile_url = reverse('idan_muteruz:profile')

    # ── helpers ───────────────────────────────────────────────────────────────

    def _post_login(self, next_param=None, follow=False):
        url = self.login_url
        if next_param:
            url = f'{url}?next={next_param}'
        return self.client.post(
            url,
            {'username': self.user.username, 'password': self.password},
            follow=follow,
        )

    # ── login — external next is blocked ─────────────────────────────────────

    def test_login_external_next_redirects_to_dashboard(self):
        """An external ``next`` URL must be rejected; user lands on dashboard."""
        response = self._post_login(next_param='http://evil.com/')
        self.assertRedirects(
            response,
            self.dashboard_url,
            fetch_redirect_response=False,
        )

    def test_login_protocol_relative_next_is_blocked(self):
        """Protocol-relative ``//evil.com`` must be rejected."""
        response = self._post_login(next_param='//evil.com/steal')
        self.assertRedirects(
            response,
            self.dashboard_url,
            fetch_redirect_response=False,
        )

    def test_login_internal_next_is_honoured(self):
        """A safe same-host ``next`` URL must be followed after login."""
        response = self._post_login(next_param=self.profile_url)
        self.assertRedirects(
            response,
            self.profile_url,
            fetch_redirect_response=False,
        )

    def test_login_next_in_post_body_is_validated(self):
        """``next`` supplied in the POST body (hidden field) must also be
        validated — external targets must be rejected."""
        response = self.client.post(
            self.login_url,
            {
                'username': self.user.username,
                'password': self.password,
                'next': 'http://evil.com/',
            },
        )
        self.assertRedirects(
            response,
            self.dashboard_url,
            fetch_redirect_response=False,
        )

    def test_login_post_body_internal_next_is_honoured(self):
        """``next`` in the POST body pointing to an internal URL must work."""
        response = self.client.post(
            self.login_url,
            {
                'username': self.user.username,
                'password': self.password,
                'next': self.profile_url,
            },
        )
        self.assertRedirects(
            response,
            self.profile_url,
            fetch_redirect_response=False,
        )

    # ── logout — external next is blocked ────────────────────────────────────

    def test_logout_external_next_redirects_to_login(self):
        """An external ``next`` after logout must be rejected; user lands on login."""
        self.client.force_login(self.user)
        response = self.client.post(
            f'{self.logout_url}?next=http://evil.com/',
        )
        self.assertRedirects(
            response,
            self.login_url,
            fetch_redirect_response=False,
        )

    def test_logout_internal_next_is_honoured(self):
        """A safe same-host ``next`` after logout must be followed."""
        self.client.force_login(self.user)
        # Use the register page as an internal destination that is
        # accessible without authentication.
        response = self.client.post(
            f'{self.logout_url}?next={self.register_url}',
        )
        self.assertRedirects(
            response,
            self.register_url,
            fetch_redirect_response=False,
        )

    # ── register — external next is blocked ──────────────────────────────────

    def test_register_external_next_redirects_to_plain_login(self):
        """After registration, an external ``next`` must be rejected."""
        response = self.client.post(
            f'{self.register_url}?next=http://evil.com/',
            {
                'username': 'newuser_ortest',
                'email': 'new@example.com',
                'first_name': 'Test',
                'last_name': 'User',
                'password1': self.password,
                'password2': self.password,
            },
        )
        self.assertRedirects(
            response,
            self.login_url,
            fetch_redirect_response=False,
        )

    def test_register_protocol_relative_next_is_blocked(self):
        """Protocol-relative URLs after registration must be rejected."""
        response = self.client.post(
            f'{self.register_url}?next=//evil.com/',
            {
                'username': 'newuser_proto',
                'email': 'proto@example.com',
                'first_name': 'Test',
                'last_name': 'User',
                'password1': self.password,
                'password2': self.password,
            },
        )
        self.assertRedirects(
            response,
            self.login_url,
            fetch_redirect_response=False,
        )

    def test_register_internal_next_is_passed_to_login(self):
        """After registration with a safe ``next``, the login URL carries it."""
        response = self.client.post(
            f'{self.register_url}?next={self.profile_url}',
            {
                'username': 'newuser_internal',
                'email': 'internal@example.com',
                'first_name': 'Test',
                'last_name': 'User',
                'password1': self.password,
                'password2': self.password,
            },
        )
        expected = f'{self.login_url}?next={self.profile_url}'
        self.assertRedirects(
            response,
            expected,
            fetch_redirect_response=False,
        )

    def test_register_next_via_post_body_external_is_blocked(self):
        """``next`` in the register POST body must also be validated."""
        response = self.client.post(
            self.register_url,
            {
                'username': 'newuser_postbody',
                'email': 'postbody@example.com',
                'first_name': 'Test',
                'last_name': 'User',
                'password1': self.password,
                'password2': self.password,
                'next': 'http://evil.com/',
            },
        )
        self.assertRedirects(
            response,
            self.login_url,
            fetch_redirect_response=False,
        )

    # ── hidden-field propagation ──────────────────────────────────────────────

    def test_login_template_exposes_next_in_context(self):
        """The login template context must contain a validated ``next`` value
        so the hidden field can be rendered."""
        response = self.client.get(f'{self.login_url}?next={self.profile_url}')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['next'], self.profile_url)

    def test_login_template_external_next_is_empty_in_context(self):
        """An external ``next`` must result in an empty context value
        (so the hidden field is not rendered for unsafe URLs)."""
        response = self.client.get(
            f'{self.login_url}?next=http://evil.com/'
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context.get('next', ''), '')

    def test_register_template_exposes_next_in_context(self):
        """The register template context must contain a validated ``next`` value."""
        response = self.client.get(
            f'{self.register_url}?next={self.profile_url}'
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['next'], self.profile_url)

    def test_register_template_external_next_is_empty_in_context(self):
        """An external ``next`` must result in an empty context value for register."""
        response = self.client.get(
            f'{self.register_url}?next=http://evil.com/'
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context.get('next', ''), '')

    # ── lockout redirect — next is preserved or rejected ─────────────────────

    @override_settings(LOGIN_MAX_ATTEMPTS=3, LOGIN_LOCKOUT_SECONDS=60)
    def test_lockout_redirect_preserves_valid_next(self):
        """
        When an account is locked out, the redirect back to login must carry a
        validated internal ``next`` URL so the user does not lose their
        destination after the lockout window expires.
        """
        login_url_with_next = f'{self.login_url}?next={self.profile_url}'
        # Trigger lockout
        for _ in range(3):
            self.client.post(
                login_url_with_next,
                {'username': self.user.username, 'password': 'wrong'},
            )
        # Fourth attempt (locked) — should redirect back to login?next=/profile/
        response = self.client.post(
            login_url_with_next,
            {'username': self.user.username, 'password': self.password},
        )
        expected = f'{self.login_url}?next={self.profile_url}'
        self.assertRedirects(response, expected, fetch_redirect_response=False)

    @override_settings(LOGIN_MAX_ATTEMPTS=3, LOGIN_LOCKOUT_SECONDS=60)
    def test_lockout_redirect_drops_external_next(self):
        """
        When an account is locked out, an external ``next`` URL must be
        silently dropped — the lockout redirect must not become an open
        redirect vector.
        """
        evil_next = 'http://evil.com/'
        login_url_evil = f'{self.login_url}?next={evil_next}'
        for _ in range(3):
            self.client.post(
                login_url_evil,
                {'username': self.user.username, 'password': 'wrong'},
            )
        response = self.client.post(
            login_url_evil,
            {'username': self.user.username, 'password': self.password},
        )
        # Must redirect to plain login, not to evil.com
        self.assertRedirects(
            response, self.login_url, fetch_redirect_response=False
        )
