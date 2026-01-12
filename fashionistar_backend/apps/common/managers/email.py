import logging
import asyncio
from typing import Any, List, Optional
from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.template import TemplateDoesNotExist

logger = logging.getLogger('application')

class EmailManagerError(Exception):
    """Raise an exception if an error occurs in the email manager"""

class EmailManager:
    """
    Manages email sending with sync and async methods.
    """
    max_attempts = 3

    @classmethod
    def send_mail(cls, subject: str, recipients: List[str], context: Optional[dict[str, Any]] = None, template_name: Optional[str] = None, message: Optional[str] = None, attachments: Optional[List[tuple]] = None, fail_silently: bool = False) -> None:
        """
        Send email (sync).
        """
        try:
            if (context and template_name is None) or (template_name and context is None):
                raise EmailManagerError("context set but template_name not set Or template_name set and context not set.")
            if (context is None) and (template_name is None) and (message is None):
                raise EmailManagerError("Must set either {context and template_name} or message args.")
            html_message = None
            plain_message = message
            if context and template_name:
                html_message = render_to_string(template_name=template_name, context=context)
                plain_template_name = template_name.replace(".html", ".txt")
                try:
                    plain_message = render_to_string(plain_template_name, context=context)
                except TemplateDoesNotExist:
                    logger.warning(f"Plain text template missing: {plain_template_name}")
                    plain_message = html_message
            email = EmailMultiAlternatives(subject=subject, body=plain_message or '', from_email=settings.DEFAULT_FROM_EMAIL, to=recipients)
            if html_message:
                email.attach_alternative(html_message, "text/html")
            if attachments:
                for filename, content, mimetype in attachments:
                    email.attach(filename, content, mimetype)
            email.send(fail_silently=fail_silently)
            logger.info(f"Email sent to {recipients}")
        except Exception as e:
            logger.error(f"Error sending email: {str(e)}")
            raise

    @classmethod
    async def asend_mail(cls, subject: str, recipients: List[str], context: Optional[dict[str, Any]] = None, template_name: Optional[str] = None, message: Optional[str] = None, attachments: Optional[List[tuple]] = None, fail_silently: bool = False) -> None:
        """
        Send email (async).
        """
        try:
            # Run sync email sending in a thread to avoid blocking the event loop
            await asyncio.to_thread(
                cls.send_mail,
                subject, recipients, context, template_name, message, attachments, fail_silently
            )
            logger.info(f"Email sent (async) to {recipients}")
        except Exception as e:
            logger.error(f"Error sending email (async): {str(e)}")
            raise