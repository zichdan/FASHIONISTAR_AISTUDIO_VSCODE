# admin_backend/models/sms_backend_config.py

from django.db import models
from apps.common.models import TimeStampedModel
import logging

logger = logging.getLogger('application')

class SMSBackendConfig(TimeStampedModel):
    """
    Configuration for SMS backend providers.
    Allows dynamic selection of SMS provider via admin interface.
    """

    PROVIDER_CHOICES = [
        ('twilio', 'Twilio'),
        ('termii', 'Termii'),
        ('bulksmsNG', 'BulkSMS Nigeria'),
    ]

    provider = models.CharField(
        max_length=20,
        choices=PROVIDER_CHOICES,
        default='twilio',
        help_text="SMS provider to use."
    )
    is_active = models.BooleanField(
        default=False,
        help_text="Whether this configuration is active."
    )
    api_key = models.CharField(
        max_length=255,
        blank=True,
        help_text="API key for the provider."
    )
    api_secret = models.CharField(
        max_length=255,
        blank=True,
        help_text="API secret for the provider."
    )
    sender_id = models.CharField(
        max_length=20,
        blank=True,
        help_text="Sender ID for SMS."
    )
    base_url = models.URLField(
        blank=True,
        help_text="Base URL for API calls (if needed)."
    )

    class Meta:
        verbose_name = "SMS Backend Config"
        verbose_name_plural = "SMS Backend Configs"

    def __str__(self):
        return f"{self.provider} ({'Active' if self.is_active else 'Inactive'})"

    def save(self, *args, **kwargs):
        """
        Ensure only one active config at a time.
        """
        try:
            if self.is_active:
                # Deactivate other configs
                SMSBackendConfig.objects.filter(is_active=True).exclude(pk=self.pk).update(is_active=False)
            super().save(*args, **kwargs)
            logger.info(f"SMS config saved: {self.provider}")
        except Exception as e:
            logger.error(f"Error saving SMS config: {str(e)}")
            raise