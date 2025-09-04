from django.urls import path
from .views import signup, login, forgot_password, reset_password, logout, google_login, onboarding, google_oauth_test, generate_oauth_url

urlpatterns = [
    path('signup/', signup, name='signup'),
    path('login/', login, name='login'),
    path('forgot-password/', forgot_password, name='forgot_password'),
    path('reset-password/<uidb64>/<token>/', reset_password, name='reset_password'),
    path('logout/', logout, name='logout'),
    path('onboarding/', onboarding, name='onboarding'),
    path('google-login/', google_login, name='google-login'),
    path('google-test/', google_oauth_test, name='google-test'),  # Test endpoint
    path('oauth-url/', generate_oauth_url, name='oauth-url'),  # Generate fresh OAuth URL
]
