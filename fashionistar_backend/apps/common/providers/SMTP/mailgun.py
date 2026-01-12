# apps/common/providers/SMTP/mailgun.py

import logging
import asyncio
from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.template import TemplateDoesNotExist

logger = logging.getLogger('application')

class MailgunEmailProvider:
    """
    Email provider using Mailgun via django-anymail.
    Sends both plain text and HTML emails with full template support.
    """

    def __init__(self):
        """
        Initialize Mailgun provider with configuration from settings.
        """
        self.from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@fashionistar.com')

    def send(self, subject: str, recipients: list, context: dict = None, template_name: str = None, message: str = None, attachments: list = None, fail_silently: bool = False) -> None:
        """
        Send email synchronously via Mailgun.

        Args:
            subject (str): Email subject.
            recipients (list): List of recipient email addresses.
            context (dict): Template context (optional).
            template_name (str): Template filename (optional).
            message (str): Plain text message (optional).
            attachments (list): List of (filename, content, mimetype) tuples.
            fail_silently (bool): Whether to suppress exceptions.

        Raises:
            ValueError: If arguments are invalid.
            Exception: If email sending fails and fail_silently is False.
        """
        try:
            if (context and template_name is None) or (template_name and context is None):
                raise ValueError("context set but template_name not set Or template_name set and context not set.")
            if (context is None) and (template_name is None) and (message is None):
                raise ValueError("Must set either {context and template_name} or message args.")
            
            html_message = None
            plain_message = message
            
            # Render templates if provided
            if context and template_name:
                html_message = render_to_string(template_name=template_name, context=context)
                plain_template_name = template_name.replace('.html', '.txt')
                try:
                    plain_message = render_to_string(plain_template_name, context=context)
                except TemplateDoesNotExist:
                    logger.warning(f"Plain text template missing: {plain_template_name}")
                    plain_message = html_message
            
            # Create email with both plain text and HTML
            email = EmailMultiAlternatives(
                subject=subject,
                body=plain_message or '',
                from_email=self.from_email,
                to=recipients
            )
            
            if html_message:
                email.attach_alternative(html_message, 'text/html')
            
            if attachments:
                for filename, content, mimetype in attachments:
                    email.attach(filename, content, mimetype)
            
            email.send(fail_silently=fail_silently)
            logger.info(f"Email sent via Mailgun to {recipients}")
        except Exception as e:
            logger.error(f"Error sending email via Mailgun: {str(e)}")
            if not fail_silently:
                raise

    async def asend(self, subject: str, recipients: list, context: dict = None, template_name: str = None, message: str = None, attachments: list = None, fail_silently: bool = False) -> None:
        """
        Send email asynchronously via Mailgun.
        Wraps the synchronous send method using asyncio.to_thread.

        Args:
            subject (str): Email subject.
            recipients (list): List of recipient email addresses.
            context (dict): Template context (optional).
            template_name (str): Template filename (optional).
            message (str): Plain text message (optional).
            attachments (list): List of (filename, content, mimetype) tuples.
            fail_silently (bool): Whether to suppress exceptions.

        Raises:
            Exception: If email sending fails and fail_silently is False.
        """
        try:
            await asyncio.to_thread(
                self.send, subject, recipients, context, template_name, message, attachments, fail_silently
            )
            logger.info(f"Email sent (async) via Mailgun to {recipients}")
        except Exception as e:
            logger.error(f"Error sending email (async) via Mailgun: {str(e)}")
            if not fail_silently:
                raise
