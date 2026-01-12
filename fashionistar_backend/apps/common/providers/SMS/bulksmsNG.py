# apps/common/providers/SMS/bulksmsNG.py

import httpx
import logging
from django.conf import settings

# Initialize application logger for detailed tracking of BulkSMS NG operations
logger = logging.getLogger('application')

class BulksmsNGSMSProvider:
    """
    SMS Provider Implementation for BulkSMS Nigeria.

    This class encapsulates the logic for sending SMS messages via BulkSMS Nigeria's REST API.
    It uses httpx for both synchronous and asynchronous HTTP requests, ensuring
    non-blocking I/O operations in async contexts.

    Key Features:
    - Synchronous and Asynchronous Sending: Supports both sync and async workflows.
    - HTTP-Based: Uses httpx for reliable, modern HTTP client functionality.
    - Robust Error Handling: Comprehensive try-except blocks with detailed logging.
    - Configuration-Driven: Reads API credentials from Django settings.
    - Production-Ready: Includes validation, timeout handling, and response parsing.

    Usage:
        Instantiate the provider and call send() for sync or asend() for async operations.
        This provider is dynamically selected by DatabaseConfiguredSMSBackend based on admin config.
    """

    BASE_URL = "https://www.bulksmsnigeria.com/api/v1/sms/create"

    def __init__(self):
        """
        Initializes the BulkSMS NG Provider with configuration from Django settings.

        This constructor retrieves API token and sender ID from settings,
        ensuring all necessary parameters are available before attempting to send messages.

        Raises:
            ValueError: If required BulkSMS NG settings are missing.
        """
        try:
            self.api_token = getattr(settings, 'BULKSMS_NG_API_TOKEN', '')
            self.sender_id = getattr(settings, 'BULKSMS_NG_SENDER_ID', 'Fashionistar')

            if not self.api_token:
                raise ValueError("BulkSMS NG API token is required in settings (BULKSMS_NG_API_TOKEN).")

            logger.info("✅ BulkSMS NG Provider initialized successfully.")

        except Exception as e:
            logger.error(f"❌ Failed to initialize BulkSMS NG Provider: {e}")
            raise

    def send(self, to: str, body: str) -> str:
        """
        Sends an SMS message synchronously via BulkSMS Nigeria's REST API.

        This method constructs the API payload, makes an HTTP POST request using httpx,
        and parses the response to extract the message ID. It includes input validation
        and comprehensive error handling for reliability.

        Args:
            to (str): The recipient's phone number (E.164 format recommended).
            body (str): The text content of the SMS message.

        Returns:
            str: The message ID returned by BulkSMS NG for tracking the sent message.

        Raises:
            ValueError: If input parameters are invalid.
            Exception: If the API call fails or returns an error response.
        """
        try:
            if not to or not body:
                raise ValueError("Recipient phone number ('to') and message body ('body') are required.")

            payload = {
                'api_token': self.api_token,
                'to': to,
                'from': self.sender_id,
                'body': body,
                'dnd': 1  # Skip DND (Do Not Disturb) numbers
            }

            # Make synchronous HTTP request with timeout
            response = httpx.post(self.BASE_URL, json=payload, timeout=30.0)
            response.raise_for_status()  # Raise for HTTP errors

            data = response.json()

            # Check for success in BulkSMS NG's response format
            if data.get('status') == 'success':
                message_id = str(data.get('data', {}).get('id', 'unknown'))
                logger.info(f"✅ SMS sent via BulkSMS NG to {to}, Message ID: {message_id}")
                return message_id
            else:
                error_message = data.get('message', 'Unknown API error')
                raise Exception(f"BulkSMS NG API error: {error_message}")

        except ValueError as ve:
            logger.error(f"❌ Validation error in BulkSMS NG send: {ve}")
            raise
        except httpx.HTTPStatusError as he:
            logger.error(f"❌ HTTP error in BulkSMS NG send to {to}: {he}")
            raise Exception(f"BulkSMS NG HTTP error: {he}")
        except Exception as e:
            logger.error(f"❌ Error sending SMS via BulkSMS NG to {to}: {e}", exc_info=True)
            raise Exception(f"BulkSMS NG SMS send failed: {e}")

    async def asend(self, to: str, body: str) -> str:
        """
        Sends an SMS message asynchronously via BulkSMS Nigeria's REST API.

        This async method uses httpx.AsyncClient for non-blocking HTTP requests,
        ensuring compatibility with asyncio event loops. It mirrors the synchronous
        send method but operates in an asynchronous context.

        Args:
            to (str): The recipient's phone number.
            body (str): The text content of the SMS message.

        Returns:
            str: The message ID returned by BulkSMS NG.

        Raises:
            Exception: If the async operation or API call fails.
        """
        try:
            if not to or not body:
                raise ValueError("Recipient phone number ('to') and message body ('body') are required.")

            payload = {
                'api_token': self.api_token,
                'to': to,
                'from': self.sender_id,
                'body': body,
                'dnd': 1  # Skip DND (Do Not Disturb) numbers
            }

            # Make asynchronous HTTP request with timeout
            async with httpx.AsyncClient() as client:
                response = await client.post(self.BASE_URL, json=payload, timeout=30.0)
                response.raise_for_status()

                data = response.json()

                if data.get('status') == 'success':
                    message_id = str(data.get('data', {}).get('id', 'unknown'))
                    logger.info(f"✅ SMS sent (async) via BulkSMS NG to {to}, Message ID: {message_id}")
                    return message_id
                else:
                    error_message = data.get('message', 'Unknown API error')
                    raise Exception(f"BulkSMS NG API error: {error_message}")

        except ValueError as ve:
            logger.error(f"❌ Validation error in async BulkSMS NG send: {ve}")
            raise
        except httpx.HTTPStatusError as he:
            logger.error(f"❌ HTTP error in async BulkSMS NG send to {to}: {he}")
            raise Exception(f"BulkSMS NG HTTP error: {he}")
        except Exception as e:
            logger.error(f"❌ Error in async BulkSMS NG SMS send to {to}: {e}", exc_info=True)
            raise Exception(f"Async BulkSMS NG SMS send failed: {e}")
