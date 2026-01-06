# apps/authentication/services/google_service.py

from google.oauth2 import id_token
from google.auth.transport import requests
from django.conf import settings
from apps.authentication.models import UnifiedUser
import logging

logger = logging.getLogger('application')

class GoogleAuthService:
    """
    Handles Server-Side Verification of Google ID Tokens sent from the Client.
    """

    @staticmethod
    async def verify_and_login(token: str):
        """
        Verifies the ID token with Google's servers.

        Args:
            token (str): The JWT ID Token from the client.

        Returns:
            User: The authenticated user instance.

        Raises:
            ValueError: If token is invalid/expired.
        """
        try:
            # Verify token
            id_info = id_token.verify_oauth2_token(
                token, requests.Request(), settings.GOOGLE_CLIENT_ID
            )

            email = id_info['email']

            # Find or create user
            user, created = await UnifiedUser.objects.aget_or_create(
                email=email,
                defaults={
                    'auth_provider': UnifiedUser.PROVIDER_GOOGLE,
                    'is_verified': True,
                    'role': UnifiedUser.ROLE_CLIENT
                }
            )

            if created:
                logger.info(f"New User Registered via Google: {email}")
            else:
                logger.info(f"User logged in via Google: {email}")

            return user

        except ValueError as e:
            logger.error(f"Google Auth Failed: {str(e)}")
            raise Exception("Invalid Google Token")
        except Exception as e:
            logger.error(f"Unexpected error in Google Auth: {str(e)}")
            raise Exception("Google authentication failed.")