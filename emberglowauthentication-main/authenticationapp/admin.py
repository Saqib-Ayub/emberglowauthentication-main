from django.contrib import admin
from .models import CustomUser  # Import your custom user model

# Register your CustomUser model
admin.site.register(CustomUser)

from django.contrib import admin
from .models import Onboarding

@admin.register(Onboarding)
class OnboardingAdmin(admin.ModelAdmin):
    list_display = ['user', 'age_range', 'menopause_phase', 'language', 'region']
    search_fields = ['user__email', 'age_range', 'language', 'region']
