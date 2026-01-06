# apps/authentication/services/auth_service.py

from django.contrib.auth import authenticate
from django.contrib.auth.models import update_last_login
from rest_framework_simplejwt.tokens import RefreshToken
from apps.authentication.types.auth_schemas import LoginSchema
import logging
import redis
from django.conf import settings

logger = logging.getLogger('application')

class AuthService:
    """
    Handles core authentication logic: login, register, logout.
    """

    @staticmethod
    async def login(data: LoginSchema, request=None):
        """
        Authenticates a user and issues JWT tokens.

        Args:
            data (LoginSchema): Validated login data.
            request: The HTTP request object for audit logging.

        Returns:
            dict: Access and refresh tokens.

        Raises:
            Exception: On authentication failure.
        """
        try:
            user = await authenticate(
                email=data.email_or_phone if '@' in data.email_or_phone else None,
                phone=data.email_or_phone if not '@' in data.email_or_phone else None,
                password=data.password
            )

            if not user:
                logger.warning(f"Failed login attempt for {data.email_or_phone}")
                raise Exception("Invalid credentials.")

            # Update last login
            await update_last_login(None, user)

            # Audit logging
            if request:
                user_agent = request.META.get('HTTP_USER_AGENT', '')
                ip_address = request.META.get('REMOTE_ADDR', '')
                browser = user_agent.split('/')[0] if '/' in user_agent else user_agent
                logger.info(f"User {user.email} logged in. IP: {ip_address}, Browser: {browser}, User-Agent: {user_agent}")

            # Issue tokens
            refresh = RefreshToken.for_user(user)
            tokens = {
                'access': str(refresh.access_token),
                'refresh': str(refresh)
            }

            logger.info(f"User {user.email} logged in successfully.")
            return tokens

        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            raise Exception("Login failed.")

    # Similarly for register, logout, etc.