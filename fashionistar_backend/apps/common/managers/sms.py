import logging
import asyncio
import importlib
from django.conf import settings

logger = logging.getLogger('application')

class SMSManagerError(Exception):
    """Raise an exception if an error occurs in the SMS manager"""

class SMSManager:
    """
    Manages SMS sending with sync and async methods.
    Dynamically selects provider based on admin_backend config.
    """

    @classmethod
    def _get_provider(cls):
        """
        Dynamically load the SMS provider based on config.
        """
        try:
            from admin_backend.models import SMSBackendConfig
            config = SMSBackendConfig.objects.filter(is_active=True).first()
            if not config:
                logger.warning("No active SMS provider configured, using default Twilio")
                provider_name = 'twilio'
            else:
                provider_name = config.provider.lower()
            
            # Import the provider module
            module = importlib.import_module(f'apps.common.providers.SMS.{provider_name}')
            provider_class = getattr(module, f'{provider_name.capitalize()}SMSProvider')
            return provider_class()
        except Exception as e:
            logger.error(f"Error loading SMS provider: {str(e)}, falling back to Twilio")
            from apps.common.providers.SMS.twilio import TwilioSMSProvider
            return TwilioSMSProvider()

    @classmethod
    def send_sms(cls, to: str, body: str) -> str:
        """
        Send SMS (sync).
        """
        try:
            provider = cls._get_provider()
            return provider.send(to, body)
        except Exception as e:
            logger.error(f"Error sending SMS: {str(e)}")
            raise SMSManagerError(f"Failed to send SMS to {to}: {e}")

    @classmethod
    async def asend_sms(cls, to: str, body: str) -> str:
        """
        Send SMS (async).
        """
        try:
            provider = cls._get_provider()
            return await provider.asend(to, body)
        except Exception as e:
            logger.error(f"Error sending SMS (async): {str(e)}")
            raise SMSManagerError(f"Failed to send SMS to {to}: {e}")