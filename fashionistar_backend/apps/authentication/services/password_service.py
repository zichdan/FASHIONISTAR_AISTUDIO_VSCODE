# apps/authentication/services/password_service.py

from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth import get_user_model
from apps.authentication.models import UnifiedUser
from utilities.managers.email import EmailManager
from utilities.managers.sms import SMSManager
from .otp_service import OTPService
import logging

logger = logging.getLogger('application')
User = get_user_model()

class PasswordService:
    """
    Handles password reset and recovery logic.
    """

    @staticmethod
    async def request_password_reset(email_or_phone: str):
        """
        Initiates password reset for email or phone.

        Args:
            email_or_phone (str): User's email or phone.

        Returns:
            str: Success message.
        """
        try:
            if '@' in email_or_phone:
                user = await User.objects.aget(email=email_or_phone)
                # Send email
                token = default_token_generator.make_token(user)
                uid = urlsafe_base64_encode(force_bytes(user.pk))
                reset_link = f"https://yourdomain.com/reset/{uid}/{token}/"
                EmailManager.send_mail(
                    subject="Password Reset",
                    recipients=[user.email],
                    template_name="password_reset.html",
                    context={"reset_link": reset_link}
                )
                logger.info(f"Password reset email sent to {user.email}")
            else:
                user = await User.objects.aget(phone=email_or_phone)
                # Send SMS
                otp = OTPService.generate_otp(user.id, 'reset')
                SMSManager.send_sms(user.phone, f"Your reset OTP: {otp}")
                logger.info(f"Password reset SMS sent to {user.phone}")

            return "Password reset initiated successfully."
        except User.DoesNotExist:
            logger.warning(f"Password reset attempted for non-existent user: {email_or_phone}")
            raise Exception("User not found.")
        except Exception as e:
            logger.error(f"Error in password reset request: {str(e)}")
            raise Exception("Failed to initiate password reset.")

    @staticmethod
    async def confirm_password_reset(uidb64: str, token: str, new_password: str):
        """
        Confirms password reset.

        Args:
            uidb64 (str): Encoded user ID.
            token (str): Reset token.
            new_password (str): New password.

        Returns:
            str: Success message.
        """
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = await User.objects.aget(pk=uid)

            if default_token_generator.check_token(user, token):
                user.set_password(new_password)
                await user.asave()
                logger.info(f"Password reset successful for user {user.email}")
                return "Password reset successful."
            else:
                raise Exception("Invalid token.")
        except Exception as e:
            logger.error(f"Error in password reset confirmation: {str(e)}")
            raise Exception("Failed to reset password.")