# admin_backend/backends/__init__.py

"""
Backends package for admin_backend.

This package contains dynamic backend implementations for email and SMS providers,
enabling runtime configuration and selection of third-party services.
"""

from .email_backends import DatabaseConfiguredEmailBackend
from .sms_backends import DatabaseConfiguredSMSBackend

__all__ = ['DatabaseConfiguredEmailBackend', 'DatabaseConfiguredSMSBackend']