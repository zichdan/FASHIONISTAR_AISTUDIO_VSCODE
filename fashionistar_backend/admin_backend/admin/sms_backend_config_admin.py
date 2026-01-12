# admin_backend/admin/sms_backend_config_admin.py

from django.contrib import admin
from django import forms
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _  # For internationalization
from admin_backend.models import SMSBackendConfig
import logging

application_logger = logging.getLogger('application')

class SMSBackendConfigAdminForm(forms.ModelForm):
    class Meta:
        model = SMSBackendConfig
        fields = '__all__'  # Or specify the fields you want

@admin.register(SMSBackendConfig)
class SMSBackendConfigAdmin(admin.ModelAdmin):
    form = SMSBackendConfigAdminForm
    list_display = ['sms_backend', 'created_at', 'updated_at']  # Display updated_at
    readonly_fields = ('created_at', 'updated_at')  # Make them read-only

    def has_add_permission(self, request):
        # Only allow adding if no instance exists
        return not SMSBackendConfig.objects.exists()

    def has_delete_permission(self, request, obj=None):
        # Disallow deletion from the Admin View.
        return False

    fieldsets = (
        ('SMS Configuration', {
            'fields': ('sms_backend',),
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',),  # Collapse the timestamps section by default
        }),
    )