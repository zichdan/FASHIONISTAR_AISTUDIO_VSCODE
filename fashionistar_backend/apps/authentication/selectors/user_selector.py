# apps/authentication/selectors/user_selector.py

from django.db import models
from apps.authentication.models import UnifiedUser
import logging

logger = logging.getLogger('application')

class UserSelector:
    """
    Handles optimized read queries for User data.
    """

    @staticmethod
    def get_user_profile(user_id: int):
        """
        Retrieves user profile with related data.

        Args:
            user_id (int): The user ID.

        Returns:
            User or None: The user instance.
        """
        try:
            return UnifiedUser.objects.select_related().get(pk=user_id, is_deleted=False)
        except UnifiedUser.DoesNotExist:
            logger.warning(f"User {user_id} not found")
            return None
        except Exception as e:
            logger.error(f"Error retrieving user profile: {str(e)}")
            return None