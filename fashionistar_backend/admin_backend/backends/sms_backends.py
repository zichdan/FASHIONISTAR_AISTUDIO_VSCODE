# admin_backend/backends/sms_backends.py

import logging
from django.apps import apps
from django.conf import settings
from django.utils.module_loading import import_string

application_logger = logging.getLogger('application')

class DatabaseConfiguredSMSBackend:
    """
    Dynamic SMS Backend that selects and configures the active SMS provider from the database.

    This backend mirrors the email backend architecture, providing a unified interface
    for sending SMS messages through various third-party providers (Twilio, Termii, BulkSMS NG).
    It dynamically loads the provider class based on the active configuration in SMSBackendConfig.

    Key Features:
    - Dynamic Provider Selection: Reads from admin_backend.SMSBackendConfig to determine the active provider.
    - Fallback Mechanism: Defaults to Twilio if no configuration exists or loading fails.
    - Unified Interface: Provides a consistent send_messages method regardless of the underlying provider.
    - Robust Error Handling: Comprehensive logging and exception management for production reliability.
    - Async Support: Designed to work seamlessly with both sync and async contexts.

    Usage:
        This backend is intended to be used by SMSManager for dispatching messages.
        It abstracts the complexity of provider-specific implementations.
    """

    def __init__(self, *args, **kwargs):
        """
        Initializes the SMS backend by loading the active provider configuration.

        This method queries the SMSBackendConfig model to retrieve the selected provider path,
        dynamically imports the provider class, and instantiates it. If any step fails,
        it falls back to the default Twilio provider to ensure system continuity.

        Args:
            *args: Variable positional arguments (passed to provider constructor if needed).
            **kwargs: Variable keyword arguments (passed to provider constructor if needed).

        Raises:
            Exception: Propagates critical errors during initialization, logged for debugging.
        """
        super().__init__(*args, **kwargs)
        try:
            # Dynamically retrieve the SMSBackendConfig model to avoid import issues
            SMSBackendConfig = apps.get_model('admin_backend', 'SMSBackendConfig')
            config = SMSBackendConfig.objects.first()

            if config and config.sms_backend:
                provider_path = config.sms_backend
                application_logger.info(f"Using SMS backend from database config: {provider_path}")
            else:
                provider_path = 'apps.common.providers.SMS.twilio.TwilioSMSProvider'
                application_logger.warning("No SMSBackendConfig found, using default Twilio provider.")

            # Dynamically import and instantiate the provider class
            provider_class = import_string(provider_path)
            self.sms_provider = provider_class()
            application_logger.info(f"SMS Backend initialized with provider: {provider_path}")

        except Exception as e:
            application_logger.error(f"Critical error initializing SMS backend: {e}", exc_info=True)
            # Fallback to Twilio to prevent system failure
            from apps.common.providers.SMS.twilio import TwilioSMSProvider
            self.sms_provider = TwilioSMSProvider()
            application_logger.info("Fallback: SMS Backend initialized with Twilio provider.")

    def send_messages(self, sms_messages):
        """
        Sends a batch of SMS messages using the configured provider.

        This method provides a unified interface for sending multiple SMS messages,
        delegating the actual sending to the dynamically selected provider's send method.
        It supports both single messages and batches, with comprehensive error handling.

        Args:
            sms_messages (list): A list of SMS message dictionaries, each containing:
                - 'to' (str): Recipient phone number.
                - 'body' (str): Message content.
                Additional provider-specific fields may be included.

        Returns:
            list: A list of message IDs or status strings returned by the provider for each message.

        Raises:
            Exception: If any message fails to send, with detailed logging for troubleshooting.
        """
        results = []
        try:
            for message in sms_messages:
                to = message.get('to')
                body = message.get('body')
                if not to or not body:
                    application_logger.error(f"Invalid SMS message format: {message}")
                    raise ValueError("SMS message must contain 'to' and 'body' fields.")

                # Delegate to the provider's send method
                result = self.sms_provider.send(to, body)
                results.append(result)
                application_logger.info(f"SMS sent successfully to {to} via {self.sms_provider.__class__.__name__}")

            application_logger.info(f"Batch SMS sending completed: {len(results)} messages sent.")
            return results

        except Exception as e:
            application_logger.error(f"Error sending SMS batch: {e}", exc_info=True)
            raise

    async def asend_messages(self, sms_messages):
        """
        Asynchronously sends a batch of SMS messages using the configured provider.

        This async version ensures non-blocking operations in modern Django async views.
        It wraps the synchronous send_messages method using asyncio.to_thread to prevent
        blocking the event loop during I/O operations.

        Args:
            sms_messages (list): Same as send_messages.

        Returns:
            list: Same as send_messages.

        Raises:
            Exception: Same as send_messages, with async context logging.
        """
        try:
            # Offload the blocking operation to a separate thread
            import asyncio
            return await asyncio.to_thread(self.send_messages, sms_messages)
        except Exception as e:
            application_logger.error(f"Async error sending SMS batch: {e}", exc_info=True)
            raise