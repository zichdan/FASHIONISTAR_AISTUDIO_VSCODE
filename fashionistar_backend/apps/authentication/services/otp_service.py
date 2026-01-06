# apps/authentication/services/otp_service.py

import secrets
import redis
from django.conf import settings
from utilities.django_redis import encrypt_otp, decrypt_otp  # From existing codebase
import logging

logger = logging.getLogger('application')

class OTPService:
    """
    Handles the generation, storage (Redis), and verification of One-Time Passwords (OTP).
    Uses encryption for security.
    """

    @staticmethod
    def generate_otp(user_id: int, purpose: str = 'login') -> str:
        """
        Generates a 6-digit cryptographically secure OTP.

        Args:
            user_id (int): The ID of the user.
            purpose (str): The purpose of the OTP (e.g., 'login', 'reset').

        Returns:
            str: The 6-digit OTP.
        """
        try:
            # Generate secure OTP
            otp_code = secrets.randbelow(1000000)
            otp_str = f"{otp_code:06d}"

            # Encrypt OTP
            encrypted_otp = encrypt_otp(otp_str)

            # Store in Redis with TTL
            redis_client = redis.Redis.from_url(settings.REDIS_URL)
            key = f"otp:{user_id}:{purpose}"
            redis_client.set(key, encrypted_otp, ex=300)  # 5 minutes

            logger.info(f"Generated OTP for user {user_id}, purpose {purpose}")
            return otp_str
        except Exception as e:
            logger.error(f"Error generating OTP: {str(e)}")
            raise Exception("Failed to generate OTP.")

    @staticmethod
    def verify_otp(user_id: int, otp: str, purpose: str = 'login') -> bool:
        """
        Verifies the OTP against Redis.

        Args:
            user_id (int): The ID of the user.
            otp (str): The OTP to verify.
            purpose (str): The purpose of the OTP.

        Returns:
            bool: True if valid, False otherwise.
        """
        try:
            redis_client = redis.Redis.from_url(settings.REDIS_URL)
            key = f"otp:{user_id}:{purpose}"
            encrypted_otp = redis_client.get(key)

            if not encrypted_otp:
                return False

            decrypted_otp = decrypt_otp(encrypted_otp.decode())
            if decrypted_otp == otp:
                redis_client.delete(key)  # One-time use
                logger.info(f"Verified OTP for user {user_id}")
                return True
            return False
        except Exception as e:
            logger.error(f"Error verifying OTP: {str(e)}")
            return False