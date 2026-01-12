# admin_backend/models/sms_backend_config.py

from django.db import models
from django.utils import timezone
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _  # For internationalization
import logging

logger = logging.getLogger('application')

class SMSBackendConfig(models.Model):
    """
    Configuration for SMS backend providers.
    Allows dynamic selection of SMS provider via admin interface.
    Exactly mirrors EmailBackendConfig for consistency.
    """

    SMS_BACKEND_CHOICES = [
        ('apps.common.providers.SMS.twilio.TwilioSMSProvider', 'Twilio'),
        ('apps.common.providers.SMS.termii.TermiiSMSProvider', 'Termii'),
        ('apps.common.providers.SMS.bulksmsNG.BulksmsNGSMSProvider', 'BulkSMS Nigeria'),
    ]

    sms_backend = models.CharField(
        max_length=250,  # Increased max length to match email
        choices=SMS_BACKEND_CHOICES,
        default='apps.common.providers.SMS.twilio.TwilioSMSProvider',  # Twilio as default
        verbose_name='Select SMS Backend',
        help_text=_("Choose the SMS backend you wish to use for sending SMS. Ensure API credentials are set in environment variables."),
        db_index=True  # Add a database index
    )

    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        # Get the display name of the chosen SMS backend
        return dict(self.SMS_BACKEND_CHOICES).get(self.sms_backend, "SMS Backend Configuration")

    class Meta:
        verbose_name = "SMS Backend Configuration"
        verbose_name_plural = "SMS Backend Configuration"
        indexes = [
            models.Index(fields=['sms_backend'], name='sms_backend_idx'),
        ]

    def clean(self):
        super().clean()
        if self.pk is None:  # It's a new instance
            if SMSBackendConfig.objects.exists():
                raise ValidationError(_("You cannot create a new instance once the first one is created. Instead, you can edit the already existing one to your preferred SMS provider."))

    def delete(self, *args, **kwargs):
        raise ValidationError(_("You cannot DELETE this SMS Backend Configuration instance!!!.  This configuration is required for sending SMS.!!!   You can Only EDIT to your preferred SMS provider."))

    def save(self, *args, **kwargs):
        self.full_clean()  # Ensure clean() is called before saving.
        super().save(*args, **kwargs)