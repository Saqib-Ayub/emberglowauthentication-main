from django.contrib.auth import get_user_model, authenticate
from django.contrib.auth.tokens import default_token_generator, PasswordResetTokenGenerator
from django.contrib.sites import requests
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_str
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import  APIView
import requests

from django.core.mail import send_mail
from django.conf import settings
from .serializers import UserSerializer, LoginSerializer, ForgotPasswordSerializer, ResetPasswordSerializer
from rest_framework import status

from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.urls import reverse
from django.core.mail import send_mail
from django.conf import settings
from django.views import View
from django.http import JsonResponse
from django.contrib.auth import get_user_model
from django.db.models import Q

User = get_user_model()

@api_view(['POST'])
@permission_classes([AllowAny])
def signup(request):
    serializer = UserSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        # Do NOT allow login yet
        user.is_active = False
        user.save(update_fields=["is_active"])

        # Build verification link
        uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        activation_link = f"{settings.SITE_URL}/api/auth/verify-email/{uidb64}/{token}/"

        subject = f"Verify your {getattr(settings, 'PROJECT_NAME', 'App')} account"
        message = (
            f"Hi {user.get_username()},\n\n"
            f"Please verify your email to activate your account:\n{activation_link}\n\n"
            f"If you didn’t sign up, you can ignore this email."
        )
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email], fail_silently=False)

        return Response(
            {"detail": "Signup successful. Check your email to verify your account."},
            status=status.HTTP_201_CREATED
        )

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(["POST"])
@permission_classes([AllowAny])
def login(request):
    email = request.data.get("email")
    password = request.data.get("password")

    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return Response({"detail": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

    if not user.is_active:
        return Response({"detail": "Your email is not verified. Please check your inbox and verify before logging in."}, status=status.HTTP_401_UNAUTHORIZED)

    if not user.check_password(password):
        return Response({"detail": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

    # Passed all checks → return tokens
    refresh = RefreshToken.for_user(user)
    return Response({
        "refresh": str(refresh),
        "access": str(refresh.access_token)
    }, status=status.HTTP_200_OK)



@api_view(['POST'])
@permission_classes([AllowAny])
def forgot_password(request):
    serializer = ForgotPasswordSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    email = serializer.validated_data['email']
    user = User.objects.filter(email=email).first()
    if not user:
        return Response({'detail': 'No account found with this email.'}, status=status.HTTP_400_BAD_REQUEST)

    uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
    token = default_token_generator.make_token(user)
    reset_link = f"{settings.SITE_URL}/api/auth/reset-password/{uidb64}/{token}/"

    send_mail(
        'Password Reset Request',
        f'Click the following link to reset your password: {reset_link}',
        settings.DEFAULT_FROM_EMAIL,
        [email],
        fail_silently=False,
    )
    return Response({'detail': 'Password reset link sent to your email.'}, status=status.HTTP_200_OK)


# Reset Password View (Update Password)
@api_view(["POST"])
@permission_classes([AllowAny])
def reset_password(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)

        # Validate token
        if not PasswordResetTokenGenerator().check_token(user, token):
            return Response({"detail": "Invalid or expired token"}, status=status.HTTP_400_BAD_REQUEST)

        password = request.data.get("password")
        confirm_password = request.data.get("confirm_password")

        if password != confirm_password:
            return Response({"detail": "Passwords do not match"}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(password)
        user.save()

        return Response({"detail": "Password has been reset successfully"}, status=status.HTTP_200_OK)

    except (User.DoesNotExist, ValueError, TypeError, OverflowError):
        return Response({"detail": "Invalid user or reset link."}, status=status.HTTP_400_BAD_REQUEST)

# Logout View
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def logout(request):
    try:
        refresh_token = request.data.get("refresh")
        if not refresh_token:
            return Response(data={"detail": "Refresh token is required."}, status=status.HTTP_400_BAD_REQUEST)

        # Manually expire or invalidate the refresh token
        token = RefreshToken(refresh_token)

        # Add logic here to manually remove the refresh token if blacklist method fails
        # token.blacklist()

        return Response(data={"detail": "Logout successful"}, status=status.HTTP_205_RESET_CONTENT)

    except Exception as e:
        print(f"Error: {str(e)}")
        return Response(data={"detail": "Invalid token"}, status=status.HTTP_400_BAD_REQUEST)




# User = get_user_model()

# Global variable to track used codes (for debugging)
used_codes = set()

# Google Login API View
@api_view(['POST'])
@permission_classes([AllowAny])
def google_login(request):
    authorization_code = request.data.get('code')
    
    print(f"Received request data: {request.data}")  # Debug log
    print(f"Authorization code: {authorization_code}")
    
    # Check if this code was already used (for debugging)
    if authorization_code in used_codes:
        return Response({
            'error': 'This authorization code has already been used. Get a fresh code from /api/auth/oauth-url/',
            'oauth_url_endpoint': 'GET http://127.0.0.1:8000/api/auth/oauth-url/'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    # Multiple redirect URI options for testing
    possible_redirect_uris = [
        'urn:ietf:wg:oauth:2.0:oob',  # For testing/Postman - try this first
        'http://localhost:3000/auth/callback',
        'http://127.0.0.1:3000/auth/callback', 
        'http://localhost:8080/auth/callback',
        request.data.get('redirect_uri')  # Allow custom override
    ]
    
    # Filter out None values and get unique URIs
    redirect_uris_to_try = list(filter(None, set(possible_redirect_uris)))
    
    print(f"Received request data: {request.data}")  # Debug log
    print(f"Authorization code: {authorization_code}")
    print(f"Will try redirect URIs: {redirect_uris_to_try}")

    # Ensure authorization code is provided
    if not authorization_code:
        return Response({'error': 'Authorization code is required.'}, status=status.HTTP_400_BAD_REQUEST)
    
    # Try different redirect URIs until one works
    last_error = None
    for redirect_uri in redirect_uris_to_try:
        try:
            print(f"Trying redirect URI: {redirect_uri}")
            
            # Step 1: Exchange authorization code for access token
            token_data = exchange_code_for_tokens(authorization_code, redirect_uri)
            
            # If we get here, the token exchange was successful
            print(f"Token exchange successful with redirect URI: {redirect_uri}")
            
            # Mark this code as used
            used_codes.add(authorization_code)
            
            # Step 2: Get user info from Google using the access token
            user_info = get_google_user_info(token_data['access_token'])
            
            # Step 3: Create or get the user in the database
            user = get_or_create_user(user_info)
            
            # Step 4: Generate JWT tokens for the user
            refresh = RefreshToken.for_user(user)
            access_token = refresh.access_token
            
            # Get the Google profile picture from user_info
            google_picture = user_info.get('picture', '')
            
            # Return response with the tokens and user info
            return Response({
                'access': str(access_token),
                'refresh': str(refresh),
                'user': {
                    'id': user.id,
                    'email': user.email,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'avatar': google_picture,
                },
                'used_redirect_uri': redirect_uri  # For debugging
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            last_error = str(e)
            print(f"Failed with redirect URI {redirect_uri}: {last_error}")
            continue
    
    # If all redirect URIs failed
    return Response({
        'error': f'Google login failed with all redirect URIs. Last error: {last_error}',
        'tried_redirect_uris': redirect_uris_to_try,
        'suggestion': 'Make sure one of these redirect URIs is configured in your Google Console'
    }, status=status.HTTP_400_BAD_REQUEST)

# Function to exchange authorization code for tokens
def exchange_code_for_tokens(authorization_code, redirect_uri):
    try:
        google_settings = settings.SOCIALACCOUNT_PROVIDERS['google']['APP']
        
        token_url = 'https://oauth2.googleapis.com/token'
        token_data = {
            'client_id': google_settings['client_id'],
            'client_secret': google_settings['secret'],
            'code': authorization_code,
            'grant_type': 'authorization_code',
            'redirect_uri': redirect_uri,
        }
        
        print(f"Token request data: {token_data}")  # Log the data being sent to Google
        
        response = requests.post(token_url, data=token_data, timeout=10)
        
        print(f"Google response status: {response.status_code}")
        print(f"Google response text: {response.text}")
        
        if response.status_code != 200:
            error_details = response.json() if response.headers.get('content-type') == 'application/json' else response.text
            print(f"Token exchange failed: {error_details}")
            raise Exception(f'Failed to exchange code for tokens: {error_details}')
        
        return response.json()
        
    except Exception as e:
        print(f"Exception in exchange_code_for_tokens: {str(e)}")
        raise

# Function to get user info from Google using the access token
def get_google_user_info(access_token):
    user_info_url = 'https://www.googleapis.com/oauth2/v2/userinfo'

    headers = {'Authorization': f'Bearer {access_token}'}
    response = requests.get(user_info_url, headers=headers, timeout=10)

    if response.status_code != 200:
        raise Exception(f'Failed to get user info from Google: {response.text}')

    return response.json()

# Function to get or create a user in the database based on Google user info
def get_or_create_user(user_info):
    email = user_info.get('email')
    if not email:
        raise Exception('Email not provided by Google')

    google_picture = user_info.get('picture', '')

    try:
        # Try to get an existing user
        user = User.objects.get(email=email)
        print(f"Found existing user: {user.email}")

    except User.DoesNotExist:
        # Create a new user and save in the database
        print(f"Creating new user for email: {email}")
        user = User.objects.create_user(
            username=email,
            email=email,
            first_name=user_info.get('given_name', ''),
            last_name=user_info.get('family_name', ''),
        )
        print(f"Created new user: {user.email}")

    return user


# OAuth URL generator for easy testing
@api_view(['GET'])
@permission_classes([AllowAny])
def generate_oauth_url(request):
    """Generate fresh OAuth URL for testing"""
    google_settings = settings.SOCIALACCOUNT_PROVIDERS['google']['APP']
    
    # Use urn:ietf:wg:oauth:2.0:oob for testing - this shows the code on a page
    redirect_uri = 'urn:ietf:wg:oauth:2.0:oob'
    
    oauth_url = (
        f"https://accounts.google.com/o/oauth2/auth?"
        f"client_id={google_settings['client_id']}&"
        f"redirect_uri={redirect_uri}&"
        f"scope=openid%20email%20profile&"
        f"response_type=code&"
        f"access_type=offline&"
        f"prompt=consent"  # Force consent to get fresh code
    )
    
    return Response({
        'oauth_url': oauth_url,
        'instructions': [
            '1. Click the oauth_url above',
            '2. Complete Google authorization',
            '3. Copy the authorization code from the page',
            '4. Use that fresh code in your POST request to /api/auth/google-login/'
        ],
        'note': 'Each authorization code can only be used ONCE. Always get a fresh code for testing.'
    }, status=status.HTTP_200_OK)


# Simple test endpoint for Google OAuth flow
@api_view(['GET'])
@permission_classes([AllowAny])
def google_oauth_test(request):
    """Test endpoint to help with Google OAuth setup"""
    google_settings = settings.SOCIALACCOUNT_PROVIDERS['google']['APP']
    
    # Common redirect URIs that should be configured in Google Console
    redirect_uris_for_console = [
        'http://localhost:3000/auth/callback',  # React/Next.js frontend
        'http://127.0.0.1:3000/auth/callback',  # Alternative localhost
        'http://localhost:8080/auth/callback',  # Vue.js frontend
        'urn:ietf:wg:oauth:2.0:oob',  # For Postman/testing
    ]
    
    # Generate different auth URLs for testing
    auth_urls = {}
    for uri in redirect_uris_for_console:
        auth_urls[f'auth_url_for_{uri.replace(":", "_").replace("/", "_")}'] = (
            f"https://accounts.google.com/o/oauth2/auth?"
            f"client_id={google_settings['client_id']}&"
            f"redirect_uri={uri}&"
            f"scope=openid%20email%20profile&"
            f"response_type=code&"
            f"access_type=offline"
        )
    
    return Response({
        'message': 'Google OAuth Setup Helper',
        'client_id': google_settings['client_id'],
        'google_console_setup': {
            'step_1': 'Go to https://console.cloud.google.com/apis/credentials',
            'step_2': 'Click on your OAuth 2.0 Client ID',
            'step_3': 'Add ALL these redirect URIs to Authorized redirect URIs:',
            'redirect_uris_to_add': redirect_uris_for_console
        },
        'testing_instructions': {
            'step_1': 'Add the redirect URIs above to Google Console',
            'step_2': 'Use one of the auth URLs below to get authorization code',
            'step_3': 'Copy the code from URL after Google redirects',
            'step_4': 'Send POST to /api/auth/google-login/ with the code',
            'step_5': 'The API will automatically try different redirect URIs'
        },
        'auth_urls': auth_urls,
        'postman_test_example': {
            'method': 'POST',
            'url': 'http://127.0.0.1:8000/api/auth/google-login/',
            'body': {
                'code': 'your_authorization_code_here'
            },
            'note': 'You can omit redirect_uri - the API will try multiple options'
        }
    }, status=status.HTTP_200_OK)


from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from .models import Onboarding
from .serializers import OnboardingSerializer


@api_view(['POST'])
@permission_classes([IsAuthenticated])  # Ensure only logged-in users can access
def onboarding(request):
    print("Onboarding view triggered!")
    user = request.user  # Get the current user from the request

    # Check if the user already has onboarding details
    if hasattr(user, 'onboarding'):
        return Response({"detail": "Onboarding data already exists."}, status=status.HTTP_400_BAD_REQUEST)

    # Serialize and validate the incoming data
    serializer = OnboardingSerializer(data=request.data)

    if serializer.is_valid():
        # Save the onboarding details
        onboarding_data = serializer.save(user=user)

        return Response({
            "detail": "Onboarding data saved successfully.",
            "data": OnboardingSerializer(onboarding_data).data
        }, status=status.HTTP_201_CREATED)
    else:
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)




from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from django.utils.timezone import now
from datetime import timedelta

class VerifyEmailView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (User.DoesNotExist, ValueError, TypeError, OverflowError):
            return Response({"ok": False, "message": "Invalid activation link."}, status=400)

        if user.is_active:
            return Response({"ok": True, "message": "Account already verified."})

        # Optional: Check expiry manually (24 hours)
        token_age_limit = timedelta(hours=24)
        if user.date_joined < now() - token_age_limit:
            return Response({"ok": False, "message": "Token expired. Please request a new one."}, status=400)

        if default_token_generator.check_token(user, token):
            user.is_active = True
            user.save(update_fields=["is_active"])
            return Response({"ok": True, "message": "Email verified. You can now log in."})

        return Response({"ok": False, "message": "Invalid or expired token."}, status=400)


class ResendActivationEmailView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get("email", "").strip().lower()
        if not email:
            return Response({"ok": False, "message": "Email is required."}, status=400)

        try:
            user = User.objects.get(email__iexact=email)
        except User.DoesNotExist:
            return Response({"ok": True, "message": "If the email exists, a verification link has been sent."})

        if user.is_active:
            return Response({"ok": True, "message": "Account already verified."})

        uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        activation_link = f"{settings.SITE_URL}/api/auth/verify-email/{uidb64}/{token}/"

        subject = f"Verify your {getattr(settings, 'PROJECT_NAME', 'App')} account"
        message = (
            f"Hi {user.get_username()},\n\n"
            f"Please verify your email:\n{activation_link}\n\n"
            f"This link will expire in 24 hours."
        )
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email], fail_silently=False)

        return Response({"ok": True, "message": "Verification email sent."})

