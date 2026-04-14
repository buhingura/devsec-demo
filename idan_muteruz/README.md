# idan_muteruz

A standalone Django authentication app that provides registration, login, logout, dashboard, profile management, and password change functionality.

## Features

- User registration with email validation and secure password handling
- Login and logout using Django's built-in authentication views
- Protected dashboard and profile pages
- Password change flow with success feedback
- User profile model created automatically via signals
- Admin integration for profile management
- Full test coverage for authentication flows

## Integration

1. Ensure `idan_muteruz` is added to `INSTALLED_APPS` in `devsec_demo/settings.py`.
2. Add the URL configuration to `devsec_demo/urls.py`:

```python
from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('idan_muteruz.urls', namespace='idan_muteruz')),
]
```

3. Configure the login and logout redirects in `devsec_demo/settings.py`:

```python
LOGIN_REDIRECT_URL = '/dashboard/'
LOGOUT_REDIRECT_URL = '/login/'
LOGIN_URL = '/login/'
```

## How to run

1. Activate your virtual environment.
2. Run `python manage.py migrate`.
3. Run `python manage.py runserver`.
4. Visit `/register/`, `/login/`, `/dashboard/`, and `/profile/`.

## Security considerations

- Uses Django's built-in authentication framework and forms
- CSRF protection is enabled on all forms via template tags
- Passwords are handled by Django's secure password hashing backend
- Protected views use `LoginRequiredMixin` and redirect unauthenticated users to login
- Email addresses are validated and deduplicated during registration

## Testing

Run the app tests with:

```bash
python manage.py test idan_muteruz
```
