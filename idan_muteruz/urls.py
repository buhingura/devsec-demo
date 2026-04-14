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
]
