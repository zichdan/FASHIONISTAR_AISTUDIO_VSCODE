# admin_backend/backends/email_backends.py

"""
Email Backends for Dynamic Provider Selection.

This module provides the DatabaseConfiguredEmailBackend class, which dynamically selects
and configures the active email provider based on database configuration. It supports
both synchronous and asynchronous operations for modern Django applications.

Key Features:
- Dynamic Provider Selection: Reads from admin_backend.EmailBackendConfig to determine the active provider.
- Fallback Mechanism: Defaults to Django's SMTP backend if no configuration exists or loading fails.
- Unified Interface: Provides consistent send_messages and asend_messages methods.
- Robust Error Handling: Comprehensive logging and exception management for production reliability.
- Async Support: Uses asyncio.to_thread for non-blocking operations in async contexts.

Usage:
    This backend is configured in Django settings as EMAIL_BACKEND and handles all email dispatching
    transparently based on admin selections.
"""

import asyncio
import logging
from django.core.mail.backends.base import BaseEmailBackend
from django.apps import apps
from django.conf import settings

# Initialize application logger for detailed tracking of email backend operations
application_logger = logging.getLogger('application')

class DatabaseConfiguredEmailBackend(BaseEmailBackend):
    """
    Dynamic Email Backend that selects and configures the active email provider from the database.

    This backend mirrors the SMS backend architecture, providing a unified interface
    for sending emails through various third-party providers (SMTP, Mailgun, SendGrid, etc.).
    It dynamically loads the provider class based on the active configuration in EmailBackendConfig.

    Key Features:
    - Dynamic Provider Selection: Reads from admin_backend.EmailBackendConfig to determine the active provider.
    - Fallback Mechanism: Defaults to Django's SMTP backend if no configuration exists or loading fails.
    - Unified Interface: Provides a consistent send_messages method regardless of the underlying provider.
    - Robust Error Handling: Comprehensive logging and exception management for production reliability.
    - Async Support: Designed to work seamlessly with both sync and async contexts.

    Usage:
        This backend is intended to be used as Django's EMAIL_BACKEND setting for dispatching emails.
        It abstracts the complexity of provider-specific implementations.
    """

    def __init__(self, *args, **kwargs):
        """
        Initializes the email backend by loading the active provider configuration.

        This method queries the EmailBackendConfig model to retrieve the selected provider path,
        dynamically imports the provider class, and instantiates it. If any step fails,
        it falls back to the default Django SMTP backend to ensure system continuity.

        Args:
            *args: Variable positional arguments (passed to provider constructor if needed).
            **kwargs: Variable keyword arguments (passed to provider constructor if needed).

        Raises:
            Exception: Propagates critical errors during initialization, logged for debugging.
        """
        super().__init__(*args, **kwargs)
        try:
            # Dynamically retrieve the EmailBackendConfig model to avoid import issues
            EmailBackendConfig = apps.get_model('admin_backend', 'EmailBackendConfig')
            config = EmailBackendConfig.objects.first()

            if config and config.email_backend:
                self.email_backend_path = config.email_backend
                application_logger.info(f"Using email backend from database config: {self.email_backend_path}")
            else:
                self.email_backend_path = 'django.core.mail.backends.smtp.EmailBackend'  # Default
                application_logger.warning("No EmailBackendConfig found, using default SMTP backend.")

            # Dynamically import and instantiate the email backend class
            module_path, class_name = self.email_backend_path.rsplit('.', 1)
            module = __import__(module_path, fromlist=[class_name])
            backend_class = getattr(module, class_name)
            self.email_backend = backend_class(*args, **kwargs)

            application_logger.info(f"Email Backend initialized with provider: {self.email_backend_path}")

        except Exception as e:
            application_logger.error(f"Critical error initializing email backend: {e}", exc_info=True)
            # Fallback to Django SMTP to prevent system failure
            self.email_backend_path = 'django.core.mail.backends.smtp.EmailBackend'
            from django.core.mail.backends.smtp import EmailBackend
            self.email_backend = EmailBackend(*args, **kwargs)
            application_logger.info("Fallback: Email Backend initialized with Django SMTP provider.")

    def send_messages(self, email_messages):
        """
        Sends a batch of email messages using the configured provider.

        This method provides a unified interface for sending multiple email messages,
        delegating the actual sending to the dynamically selected provider's send_messages method.
        It supports both single messages and batches, with comprehensive error handling.

        Args:
            email_messages (list): A list of EmailMessage objects to be sent.

        Returns:
            int: The number of successfully sent messages.

        Raises:
            Exception: If any message fails to send, with detailed logging for troubleshooting.
        """
        try:
            result = self.email_backend.send_messages(email_messages)
            application_logger.info(f"Email batch sending completed: {result} messages sent via {self.email_backend_path}")
            return result
        except Exception as e:
            application_logger.error(f"Error sending email batch: {e}", exc_info=True)
            raise

    async def asend_messages(self, email_messages):
        """
        Asynchronously sends a batch of email messages using the configured provider.

        This async version ensures non-blocking operations in modern Django async views.
        It wraps the synchronous send_messages method using asyncio.to_thread to prevent
        blocking the event loop during I/O operations.

        Args:
            email_messages (list): Same as send_messages.

        Returns:
            int: Same as send_messages.

        Raises:
            Exception: Same as send_messages, with async context logging.
        """
        try:
            # Offload the blocking operation to a separate thread
            return await asyncio.to_thread(self.send_messages, email_messages)
        except Exception as e:
            application_logger.error(f"Async error sending email batch: {e}", exc_info=True)
            raise