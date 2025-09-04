from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.utils import timezone


class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("The Email field must be set")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        return self.create_user(email, password, **extra_fields)


class CustomUser(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True)   # email is unique
    full_name = models.CharField(max_length=255, default="Admin User")
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    date_joined = models.DateTimeField(default=timezone.now)

    objects = CustomUserManager()

    USERNAME_FIELD = "email"          # 👈 login with email
    REQUIRED_FIELDS = ["full_name"]   # 👈 full name is required for superuser

    def __str__(self):
        return self.email


from django.db import models
from django.contrib.auth import get_user_model

User = get_user_model()

class Onboarding(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='onboarding')
    age_range = models.CharField(max_length=10)
    menopause_phase = models.CharField(max_length=100)
    language = models.CharField(max_length=50)
    region = models.CharField(max_length=100)
    goals = models.JSONField()  # This will store multiple goals as a list of strings
    voice_preference = models.BooleanField(default=False)
    communication_tone = models.CharField(max_length=50)

    def __str__(self):
        return f"Onboarding details for {self.user.email}"
