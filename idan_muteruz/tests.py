from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.contrib.auth.tokens import default_token_generator
from django.contrib.contenttypes.models import ContentType
from django.core import mail
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

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


# ---------------------------------------------------------------------------
# Password Reset Tests
# ---------------------------------------------------------------------------

@override_settings(EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend')
class PasswordResetTests(TestCase):
    """
    Tests for the 4-step password reset flow.

    The @override_settings decorator switches to Django's in-memory email
    backend for every test so that mail.outbox captures sent messages without
    any SMTP server.

    Security scenarios covered
    --------------------------
    Anti-enumeration
        Submitting a non-existent email returns the same response and the same
        page as a real one.  An attacker cannot determine which addresses are
        registered.

    Token security
        Tokens are HMAC-SHA256-based (Django's PasswordResetTokenGenerator)
        and are single-use — the moment the password is saved the hash in the
        token payload no longer matches the stored hash, invalidating the token.

    No auto-login
        post_reset_login=False forces the user to sign in explicitly after
        resetting, preventing session takeover via an intercepted email link.

    Password validation
        Django's AUTH_PASSWORD_VALIDATORS are applied to the new password.

    Email header injection
        The subject line must contain no newlines.
    """

    def setUp(self):
        self.user = User.objects.create_user(
            username='pr_test_user',
            email='reset@example.test',
            password='OldPass!1secure',
        )
        self.request_url  = reverse('idan_muteruz:password_reset')
        self.sent_url     = reverse('idan_muteruz:password_reset_sent')
        self.complete_url = reverse('idan_muteruz:password_reset_complete')

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _make_confirm_url(self, user=None):
        """Build a fresh, valid confirm URL for the given user."""
        u = user or self.user
        uid   = urlsafe_base64_encode(force_bytes(u.pk))
        token = default_token_generator.make_token(u)
        return reverse(
            'idan_muteruz:password_reset_confirm',
            kwargs={'uidb64': uid, 'token': token},
        )

    def _load_set_password_form(self, user=None):
        """
        Follow the two-step GET (token-validation redirect) and return the
        response from the set-password form page.
        Django stores the validated token in the session and redirects to
        /<uid>/set-password/ so the token is not exposed in the Referer header.
        """
        response = self.client.get(self._make_confirm_url(user), follow=True)
        return response

    # ── Step 1: Request page ─────────────────────────────────────────────────

    def test_request_page_renders(self):
        response = self.client.get(self.request_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'idan_muteruz/password_reset_request.html')

    def test_authenticated_user_redirected_away_from_request_page(self):
        """Authenticated users should use /password/change/, not the reset flow."""
        self.client.force_login(self.user)
        response = self.client.get(self.request_url)
        self.assertRedirects(
            response,
            reverse('idan_muteruz:dashboard'),
            fetch_redirect_response=False,
        )

    # ── Anti-enumeration ─────────────────────────────────────────────────────

    def test_valid_email_redirects_to_sent_page(self):
        response = self.client.post(self.request_url, {'email': 'reset@example.test'})
        self.assertRedirects(response, self.sent_url, fetch_redirect_response=False)

    def test_nonexistent_email_redirects_to_same_sent_page(self):
        """
        ANTI-ENUMERATION: a non-registered email must produce exactly the
        same redirect as a real one.  The attacker learns nothing about which
        addresses exist.
        """
        response = self.client.post(self.request_url, {'email': 'ghost@nowhere.invalid'})
        self.assertRedirects(response, self.sent_url, fetch_redirect_response=False)

    def test_nonexistent_email_sends_no_email(self):
        self.client.post(self.request_url, {'email': 'ghost@nowhere.invalid'})
        self.assertEqual(len(mail.outbox), 0)

    def test_invalid_email_format_is_rejected(self):
        response = self.client.post(self.request_url, {'email': 'not-an-email'})
        self.assertEqual(response.status_code, 200)
        self.assertFormError(response.context['form'], 'email', 'Enter a valid email address.')

    def test_inactive_user_receives_no_email(self):
        """
        Django only sends reset mail to active users with a usable password.
        An inactive account must not receive an email (response is identical
        to the active-user case — anti-enumeration is preserved).
        """
        self.user.is_active = False
        self.user.save()
        response = self.client.post(self.request_url, {'email': 'reset@example.test'})
        self.assertRedirects(response, self.sent_url, fetch_redirect_response=False)
        self.assertEqual(len(mail.outbox), 0)

    # ── Step 2: Sent page ────────────────────────────────────────────────────

    def test_sent_page_renders(self):
        response = self.client.get(self.sent_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'idan_muteruz/password_reset_sent.html')

    # ── Email contents ───────────────────────────────────────────────────────

    def test_email_is_sent_for_registered_address(self):
        self.client.post(self.request_url, {'email': 'reset@example.test'})
        self.assertEqual(len(mail.outbox), 1)

    def test_email_contains_reset_link(self):
        self.client.post(self.request_url, {'email': 'reset@example.test'})
        self.assertIn('/password/reset/', mail.outbox[0].body)

    def test_email_subject_contains_no_newlines(self):
        """
        A subject line with embedded newlines enables email header injection.
        The subject template must produce a single clean line.
        """
        self.client.post(self.request_url, {'email': 'reset@example.test'})
        subject = mail.outbox[0].subject
        self.assertNotIn('\n', subject)
        self.assertNotIn('\r', subject)

    def test_email_does_not_contain_username(self):
        """
        The email body must not expose the username — only the reset link.
        Leaking the username confirms account existence and aids phishing.
        """
        self.client.post(self.request_url, {'email': 'reset@example.test'})
        self.assertNotIn(self.user.username, mail.outbox[0].body)

    # ── Step 3: Confirm page ─────────────────────────────────────────────────

    def test_confirm_page_renders_with_valid_token(self):
        response = self._load_set_password_form()
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'idan_muteruz/password_reset_confirm.html')
        self.assertTrue(response.context['validlink'])

    def test_confirm_page_with_invalid_token_marks_link_invalid(self):
        uid = urlsafe_base64_encode(force_bytes(self.user.pk))
        url = reverse('idan_muteruz:password_reset_confirm',
                      kwargs={'uidb64': uid, 'token': 'tampered-token-xyz'})
        response = self.client.get(url, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.context['validlink'])

    def test_confirm_page_with_garbage_uid_marks_link_invalid(self):
        url = reverse('idan_muteruz:password_reset_confirm',
                      kwargs={'uidb64': 'notbase64', 'token': 'sometoken'})
        response = self.client.get(url, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.context['validlink'])

    # ── Step 4: Full happy-path reset ────────────────────────────────────────

    def test_successful_reset_redirects_to_complete(self):
        form_response = self._load_set_password_form()
        self.assertTrue(form_response.context['validlink'])

        response = self.client.post(
            form_response.wsgi_request.path,
            {'new_password1': 'NewSecure!pass99', 'new_password2': 'NewSecure!pass99'},
            follow=True,
        )
        self.assertRedirects(response, self.complete_url)

    def test_successful_reset_allows_login_with_new_password(self):
        form_response = self._load_set_password_form()
        self.client.post(
            form_response.wsgi_request.path,
            {'new_password1': 'NewSecure!pass99', 'new_password2': 'NewSecure!pass99'},
        )
        self.assertTrue(
            self.client.login(username='pr_test_user', password='NewSecure!pass99')
        )

    def test_successful_reset_rejects_old_password(self):
        form_response = self._load_set_password_form()
        self.client.post(
            form_response.wsgi_request.path,
            {'new_password1': 'NewSecure!pass99', 'new_password2': 'NewSecure!pass99'},
        )
        self.assertFalse(
            self.client.login(username='pr_test_user', password='OldPass!1secure')
        )

    def test_reset_does_not_auto_login_user(self):
        """
        post_reset_login=False: after a successful reset the session must NOT
        contain an authenticated user.  The user must explicitly sign in.
        """
        form_response = self._load_set_password_form()
        post_response = self.client.post(
            form_response.wsgi_request.path,
            {'new_password1': 'NewSecure!pass99', 'new_password2': 'NewSecure!pass99'},
            follow=True,
        )
        self.assertFalse(post_response.wsgi_request.user.is_authenticated)

    # ── Token single-use ─────────────────────────────────────────────────────

    def test_token_is_invalidated_after_successful_reset(self):
        """
        After a reset the password hash changes, so the original token no
        longer validates — reusing the link must show validlink=False.
        """
        original_confirm_url = self._make_confirm_url()
        # Complete the reset
        form_response = self.client.get(original_confirm_url, follow=True)
        self.client.post(
            form_response.wsgi_request.path,
            {'new_password1': 'NewSecure!pass99', 'new_password2': 'NewSecure!pass99'},
        )
        # Attempt to reuse the original URL
        reuse_response = self.client.get(original_confirm_url, follow=True)
        self.assertFalse(reuse_response.context['validlink'])

    # ── Password validation ──────────────────────────────────────────────────

    def test_too_short_password_is_rejected(self):
        form_response = self._load_set_password_form()
        response = self.client.post(
            form_response.wsgi_request.path,
            {'new_password1': 'short', 'new_password2': 'short'},
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'idan_muteruz/password_reset_confirm.html')
        self.assertTrue(response.context['form'].errors)

    def test_mismatched_passwords_are_rejected(self):
        form_response = self._load_set_password_form()
        response = self.client.post(
            form_response.wsgi_request.path,
            {'new_password1': 'NewSecure!pass99', 'new_password2': 'DifferentPass!99'},
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.context['form'].errors)

    # ── Step 5: Complete page ────────────────────────────────────────────────

    def test_complete_page_renders(self):
        response = self.client.get(self.complete_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'idan_muteruz/password_reset_complete.html')
