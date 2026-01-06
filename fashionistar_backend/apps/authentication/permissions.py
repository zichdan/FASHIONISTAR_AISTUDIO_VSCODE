# apps/authentication/permissions.py

from rest_framework import permissions
import logging

logger = logging.getLogger('application')

# Authentication-specific permissions can be added here if needed
# For now, we use the common permissions