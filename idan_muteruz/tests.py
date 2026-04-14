from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse


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
