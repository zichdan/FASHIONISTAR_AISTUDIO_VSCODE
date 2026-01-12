# apps/common/providers/SMS/termii.py

import httpx
import logging
from django.conf import settings

# Initialize application logger for detailed tracking of Termii SMS operations
logger = logging.getLogger('application')

class TermiiSMSProvider:
    """
    SMS Provider Implementation for Termii.

    This class encapsulates the logic for sending SMS messages via Termii's REST API.
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

    BASE_URL = "https://api.ng.termii.com/api/sms/send"

    def __init__(self):
        """
        Initializes the Termii SMS Provider with configuration from Django settings.

        This constructor retrieves API credentials and sender ID from settings,
        ensuring all necessary parameters are available before attempting to send messages.

        Raises:
            ValueError: If required Termii settings are missing.
        """
        try:
            self.api_key = getattr(settings, 'TERMII_API_KEY', '')
            self.sender_id = getattr(settings, 'TERMII_SENDER_ID', 'Fashionistar')

            if not self.api_key:
                raise ValueError("Termii API key is required in settings (TERMII_API_KEY).")

            logger.info("✅ Termii SMS Provider initialized successfully.")

        except Exception as e:
            logger.error(f"❌ Failed to initialize Termii SMS Provider: {e}")
            raise

    def send(self, to: str, body: str) -> str:
        """
        Sends an SMS message synchronously via Termii's REST API.

        This method constructs the API payload, makes an HTTP POST request using httpx,
        and parses the response to extract the message ID. It includes input validation
        and comprehensive error handling for reliability.

        Args:
            to (str): The recipient's phone number (E.164 format recommended).
            body (str): The text content of the SMS message.

        Returns:
            str: The message ID returned by Termii for tracking the sent message.

        Raises:
            ValueError: If input parameters are invalid.
            Exception: If the API call fails or returns an error response.
        """
        try:
            if not to or not body:
                raise ValueError("Recipient phone number ('to') and message body ('body') are required.")

            payload = {
                'to': to,
                'from': self.sender_id,
                'sms': body,
                'type': 'plain',
                'channel': 'generic',
                'api_key': self.api_key
            }

            # Make synchronous HTTP request with timeout
            response = httpx.post(self.BASE_URL, json=payload, timeout=30.0)
            response.raise_for_status()  # Raise for HTTP errors

            data = response.json()

            # Check for success in Termii's response format
            if data.get('code') == '20' or data.get('status') == 'success':
                message_id = data.get('message_id', 'unknown')
                logger.info(f"✅ SMS sent via Termii to {to}, Message ID: {message_id}")
                return message_id
            else:
                error_message = data.get('message', 'Unknown API error')
                raise Exception(f"Termii API error: {error_message}")

        except ValueError as ve:
            logger.error(f"❌ Validation error in Termii send: {ve}")
            raise
        except httpx.HTTPStatusError as he:
            logger.error(f"❌ HTTP error in Termii send to {to}: {he}")
            raise Exception(f"Termii HTTP error: {he}")
        except Exception as e:
            logger.error(f"❌ Error sending SMS via Termii to {to}: {e}", exc_info=True)
            raise Exception(f"Termii SMS send failed: {e}")

    async def asend(self, to: str, body: str) -> str:
        """
        Sends an SMS message asynchronously via Termii's REST API.

        This async method uses httpx.AsyncClient for non-blocking HTTP requests,
        ensuring compatibility with asyncio event loops. It mirrors the synchronous
        send method but operates in an asynchronous context.

        Args:
            to (str): The recipient's phone number.
            body (str): The text content of the SMS message.

        Returns:
            str: The message ID returned by Termii.

        Raises:
            Exception: If the async operation or API call fails.
        """
        try:
            if not to or not body:
                raise ValueError("Recipient phone number ('to') and message body ('body') are required.")

            payload = {
                'to': to,
                'from': self.sender_id,
                'sms': body,
                'type': 'plain',
                'channel': 'generic',
                'api_key': self.api_key
            }

            # Make asynchronous HTTP request with timeout
            async with httpx.AsyncClient() as client:
                response = await client.post(self.BASE_URL, json=payload, timeout=30.0)
                response.raise_for_status()

                data = response.json()

                if data.get('code') == '20' or data.get('status') == 'success':
                    message_id = data.get('message_id', 'unknown')
                    logger.info(f"✅ SMS sent (async) via Termii to {to}, Message ID: {message_id}")
                    return message_id
                else:
                    error_message = data.get('message', 'Unknown API error')
                    raise Exception(f"Termii API error: {error_message}")

        except ValueError as ve:
            logger.error(f"❌ Validation error in async Termii send: {ve}")
            raise
        except httpx.HTTPStatusError as he:
            logger.error(f"❌ HTTP error in async Termii send to {to}: {he}")
            raise Exception(f"Termii HTTP error: {he}")
        except Exception as e:
            logger.error(f"❌ Error in async Termii SMS send to {to}: {e}", exc_info=True)
            raise Exception(f"Async Termii SMS send failed: {e}")
