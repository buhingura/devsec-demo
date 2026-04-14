from django.urls import path

from . import views

app_name = 'idan_muteruz'

urlpatterns = [
    path('', views.HomeRedirectView.as_view(), name='home'),
    path('register/', views.RegisterView.as_view(), name='register'),
    path('login/', views.UserLoginView.as_view(), name='login'),
    path('logout/', views.UserLogoutView.as_view(), name='logout'),
    path('dashboard/', views.DashboardView.as_view(), name='dashboard'),
    path('profile/', views.ProfileView.as_view(), name='profile'),
    path('password/change/', views.UserPasswordChangeView.as_view(), name='password_change'),
    # Privileged route — staff / instructors / admins only
    path('admin-panel/', views.AdminPanelView.as_view(), name='admin_panel'),
    # Role assignment — staff / superusers only (POST)
    path('admin-panel/users/<int:pk>/assign-role/', views.AssignRoleView.as_view(), name='assign_role'),

    # ── Password reset — 4-step flow ────────────────────────────────────────
    # Step 1: user enters email
    path('password/reset/',
         views.UserPasswordResetView.as_view(),
         name='password_reset'),
    # Step 2: always-identical "check your inbox" page (anti-enumeration)
    path('password/reset/sent/',
         views.UserPasswordResetSentView.as_view(),
         name='password_reset_sent'),
    # Step 3: token-validated new-password form.
    # Django's PasswordResetConfirmView handles the two-step redirect internally:
    # first visit uses the real token; Django validates it, stores it in the
    # session, and redirects to the same URL but with the token replaced by the
    # sentinel string "set-password".  Because "set-password" is just the value
    # of <token> on the second visit, a single pattern handles both visits.
    path('password/reset/<uidb64>/<token>/',
         views.UserPasswordResetConfirmView.as_view(),
         name='password_reset_confirm'),
    # Step 4: success
    path('password/reset/complete/',
         views.UserPasswordResetCompleteView.as_view(),
         name='password_reset_complete'),
]
