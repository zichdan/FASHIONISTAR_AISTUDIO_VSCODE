# apps/common/utils.py

import redis
from django.conf import settings
import logging

logger = logging.getLogger('application')

def get_redis_client():
    """
    Get Redis client instance.
    """
    try:
        return redis.Redis.from_url(settings.REDIS_URL)
    except Exception as e:
        logger.error(f"Error connecting to Redis: {str(e)}")
        raise

def delete_cloudinary_asset(public_id):
    """
    Delete asset from Cloudinary.
    """
    try:
        import cloudinary.uploader
        cloudinary.uploader.destroy(public_id)
        logger.info(f"Deleted Cloudinary asset: {public_id}")
    except Exception as e:
        logger.error(f"Error deleting Cloudinary asset {public_id}: {str(e)}")
        raise