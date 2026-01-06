# apps/authentication/admin.py

from django.contrib import admin
from django.contrib import messages
from apps.authentication.models import UnifiedUser

# Custom admin with audit logs and hard delete actions can be implemented here