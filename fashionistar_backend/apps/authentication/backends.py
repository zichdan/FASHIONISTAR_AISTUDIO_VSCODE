# apps/authentication/backends.py

from django.contrib.auth.backends import BaseBackend
from django.contrib.auth import get_user_model
from apps.authentication.models import UnifiedUser
import logging

logger = logging.getLogger('application')

class UnifiedUserBackend(BaseBackend):
    """
    Authentication backend for the new UnifiedUser model.
    This allows authentication against our new user model while keeping
    the old system running in parallel.
    """

    def authenticate(self, request, username=None, password=None, **kwargs):
        """
        Authenticate a user against the UnifiedUser model.
        """
        try:
            # Try to find user by email or phone
            user = None
            if username:
                if '@' in username:
                    # Email login
                    try:
                        user = UnifiedUser.objects.get(email=username, is_deleted=False)
                    except UnifiedUser.DoesNotExist:
                        return None
                else:
                    # Phone login
                    try:
                        user = UnifiedUser.objects.get(phone=username, is_deleted=False)
                    except UnifiedUser.DoesNotExist:
                        return None

            if user and user.check_password(password) and user.is_active:
                logger.info(f"User {user} authenticated via UnifiedUser backend")
                return user
            return None
        except Exception as e:
            logger.error(f"Error in UnifiedUser authentication: {str(e)}")
            return None

    def get_user(self, user_id):
        """
        Get a user by ID from the UnifiedUser model.
        """
        try:
            return UnifiedUser.objects.get(pk=user_id, is_deleted=False)
        except UnifiedUser.DoesNotExist:
            return None
        except Exception as e:
            logger.error(f"Error getting UnifiedUser: {str(e)}")
            return None