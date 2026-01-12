# apps/common/providers/SMS/twilio.py

import asyncio
import logging
from twilio.rest import Client
from django.conf import settings

# Initialize application logger for detailed tracking of Twilio SMS operations
logger = logging.getLogger('application')

class TwilioSMSProvider:
    """
    SMS Provider Implementation for Twilio.

    This class encapsulates the logic for sending SMS messages via Twilio's REST API.
    Twilio's SDK is inherently synchronous, so we wrap blocking operations with asyncio.to_thread
    to ensure compatibility with asynchronous Django views and prevent event loop blocking.

    Key Features:
    - Synchronous Sending: Direct integration with Twilio SDK for reliable message dispatch.
    - Asynchronous Support: Async wrapper using asyncio.to_thread for non-blocking I/O.
    - Robust Error Handling: Comprehensive try-except blocks with detailed logging.
    - Configuration-Driven: Reads credentials and settings from Django settings.
    - Production-Ready: Includes validation, logging, and exception propagation.

    Usage:
        Instantiate the provider and call send() for sync or asend() for async operations.
        This provider is dynamically selected by DatabaseConfiguredSMSBackend based on admin config.
    """

    def __init__(self):
        """
        Initializes the Twilio SMS Provider with configuration from Django settings.

        This constructor sets up the Twilio client using account credentials and phone number
        retrieved from settings. It ensures all necessary parameters are available before
        attempting to send messages.

        Raises:
            ValueError: If required Twilio settings are missing.
        """
        try:
            self.account_sid = getattr(settings, 'TWILIO_ACCOUNT_SID', '')
            self.auth_token = getattr(settings, 'TWILIO_AUTH_TOKEN', '')
            self.phone_number = getattr(settings, 'TWILIO_PHONE_NUMBER', '')

            if not all([self.account_sid, self.auth_token, self.phone_number]):
                raise ValueError("Twilio credentials (ACCOUNT_SID, AUTH_TOKEN, PHONE_NUMBER) are required in settings.")

            self.client = Client(self.account_sid, self.auth_token)
            logger.info("✅ Twilio SMS Provider initialized successfully.")

        except Exception as e:
            logger.error(f"❌ Failed to initialize Twilio SMS Provider: {e}")
            raise

    def send(self, to: str, body: str) -> str:
        """
        Sends an SMS message synchronously via Twilio's REST API.

        This method creates and sends an SMS message using Twilio's SDK. It performs
        input validation, handles the API call, and returns the message SID for tracking.
        All operations are logged for audit and debugging purposes.

        Args:
            to (str): The recipient's phone number in E.164 format (e.g., '+1234567890').
            body (str): The text content of the SMS message (limited by Twilio's constraints).

        Returns:
            str: The unique Message SID returned by Twilio for the sent message.

        Raises:
            ValueError: If input parameters are invalid (e.g., empty phone or body).
            Exception: If the Twilio API call fails, with detailed error information.
        """
        try:
            if not to or not body:
                raise ValueError("Recipient phone number ('to') and message body ('body') are required.")

            # Create and send the message via Twilio SDK
            message = self.client.messages.create(
                body=body,
                from_=self.phone_number,
                to=to
            )

            logger.info(f"✅ SMS sent via Twilio to {to}, SID: {message.sid}")
            return message.sid

        except ValueError as ve:
            logger.error(f"❌ Validation error in Twilio send: {ve}")
            raise
        except Exception as e:
            logger.error(f"❌ Error sending SMS via Twilio to {to}: {e}", exc_info=True)
            raise Exception(f"Twilio SMS send failed: {e}")

    async def asend(self, to: str, body: str) -> str:
        """
        Sends an SMS message asynchronously via Twilio's REST API.

        This async wrapper ensures that the synchronous Twilio SDK call does not block
        the asyncio event loop. It offloads the blocking I/O operation to a separate thread
        using asyncio.to_thread, making it safe for use in async Django views and handlers.

        Args:
            to (str): The recipient's phone number in E.164 format.
            body (str): The text content of the SMS message.

        Returns:
            str: The unique Message SID returned by Twilio.

        Raises:
            Exception: If the async operation or underlying send fails.
        """
        try:
            # Offload the synchronous send operation to a worker thread
            message_sid = await asyncio.to_thread(self.send, to, body)
            logger.info(f"✅ SMS sent (async) via Twilio to {to}")
            return message_sid

        except Exception as e:
            logger.error(f"❌ Error in async Twilio SMS send to {to}: {e}", exc_info=True)
            raise Exception(f"Async Twilio SMS send failed: {e}")
