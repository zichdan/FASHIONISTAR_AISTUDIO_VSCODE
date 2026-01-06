# apps/authentication/urls.py

from django.urls import path
from apps.authentication.apis import auth_views, password_views

app_name = 'authentication'

urlpatterns = [
    path('login/', auth_views.LoginView.as_view(), name='login'),
    path('password-reset/', password_views.PasswordResetRequestView.as_view(), name='password_reset_request'),
    path('password-reset-confirm/', password_views.PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    # Add more URLs as needed
]