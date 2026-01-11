# apps/common/utils.py

import redis
from django.conf import settings
import logging
import time
import random
import base64
from cryptography.fernet import Fernet
from django_redis import get_redis_connection
import cloudinary.uploader

logger = logging.getLogger('application')

# Initialize Fernet cipher suite for OTP encryption/decryption
base_key = settings.SECRET_KEY.encode()
base_key = base_key.ljust(32, b'\0')[:32]
cipher_suite = Fernet(base64.urlsafe_b64encode(base_key))

REDIS_MAX_RETRIES = 3
REDIS_RETRY_DELAY = 1

def get_redis_client():
    """
    Get Redis client instance.
    """
    try:
        return redis.Redis.from_url(settings.REDIS_URL)
    except Exception as e:
        logger.error(f"Error connecting to Redis: {str(e)}")
        raise

def encrypt_otp(otp):
    """
    Encrypts the given OTP.
    """
    try:
        return cipher_suite.encrypt(otp.encode()).decode()
    except Exception as e:
        logger.error(f"OTP encryption failed: {e}")
        raise

def decrypt_otp(encrypted_otp):
    """
    Decrypts the given encrypted OTP.
    """
    try:
        return cipher_suite.decrypt(encrypted_otp.encode()).decode()
    except Exception as e:
        logger.error(f"OTP decryption failed: {e}")
        raise

def get_redis_connection_safe(max_retries=REDIS_MAX_RETRIES, retry_delay=REDIS_RETRY_DELAY):
    """
    Establishes a safe Redis connection with retries.
    """
    for attempt in range(max_retries):
        try:
            redis_conn = get_redis_connection("default")
            redis_conn.ping()
            return redis_conn
        except Exception as e:
            logger.error(f"Redis connection error (attempt {attempt + 1}/{max_retries}): {e}")
            if attempt < max_retries - 1:
                time.sleep(retry_delay)
            else:
                logger.error("Max Redis connection retries reached.")
                return None
    return None

def generate_numeric_otp(length=6):
    """
    Generates a numeric OTP.
    """
    return ''.join(random.choices('0123456789', k=length))

def get_otp_expiry_datetime():
    """
    Calculates OTP expiry datetime.
    """
    import datetime
    timestamp = time.time() + 300
    dt_object = datetime.datetime.fromtimestamp(timestamp)
    return dt_object

def delete_cloudinary_asset(public_id, resource_type="image"):
    """
    Deletes an asset from Cloudinary.
    """
    try:
        if not public_id:
            return None
        result = cloudinary.uploader.destroy(public_id, resource_type=resource_type)
        logger.info(f"Cloudinary asset {public_id} deletion result: {result}")
        return result
    except Exception as e:
        logger.error(f"Error deleting Cloudinary asset {public_id}: {e}")
        return None