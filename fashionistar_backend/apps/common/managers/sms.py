import logging
from django.conf import settings
from twilio.rest import Client

logger = logging.getLogger('application')

class SMSManagerError(Exception):
    """Raise an exception if an error occurs in the SMS manager"""

class SMSManager:
    """
    Manages SMS sending with sync and async methods.
    """

    @classmethod
    def send_sms(cls, to: str, body: str) -> str:
        """
        Send SMS (sync).
        """
        try:
            client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
            message = client.messages.create(body=body, from_=settings.TWILIO_PHONE_NUMBER, to=to)
            logger.info(f"SMS sent to {to} with SID: {message.sid}")
            return message.sid
        except Exception as e:
            logger.error(f"Error sending SMS: {str(e)}")
            raise SMSManagerError(f"Failed to send SMS to {to}: {e}")

    @classmethod
    async def asend_sms(cls, to: str, body: str) -> str:
        """
        Send SMS (async).
        """
        try:
            # Async version; wrap sync for now
            return await cls.send_sms(to, body)
        except Exception as e:
            logger.error(f"Error sending SMS (async): {str(e)}")
            raise SMSManagerError(f"Failed to send SMS to {to}: {e}")