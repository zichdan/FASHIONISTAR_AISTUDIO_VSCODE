# apps/authentication/models.py

from django.contrib.auth.models import AbstractUser
from django.db import models
from apps.common.models import TimeStampedModel, SoftDeleteModel, HardDeleteMixin
from phonenumber_field.modelfields import PhoneNumberField
import logging

logger = logging.getLogger('application')

class UnifiedUser(AbstractUser, TimeStampedModel, SoftDeleteModel, HardDeleteMixin):
    """
    The Central Identity Entity.

    Merged Fields from legacy Profile:
    - bio, phone, avatar (was image), country, city, state, address.

    New Architecture Fields:
    - auth_provider: Tracks if user signed up via Email, Phone, or Google.
    - role: RBAC (Role Based Access Control).
    """

    # Auth Providers
    PROVIDER_EMAIL = "email"
    PROVIDER_PHONE = "phone"
    PROVIDER_GOOGLE = "google"

    PROVIDER_CHOICES = [
        (PROVIDER_EMAIL, "Email"),
        (PROVIDER_PHONE, "Phone"),
        (PROVIDER_GOOGLE, "Google"),
    ]

    # Roles
    ROLE_VENDOR = "vendor"
    ROLE_CLIENT = "client"
    ROLE_STAFF = "staff"  # Support/Reviewers
    ROLE_ADMIN = "admin"

    ROLE_CHOICES = [
        (ROLE_VENDOR, "Vendor"),
        (ROLE_CLIENT, "Client"),
        (ROLE_STAFF, "Staff"),
        (ROLE_ADMIN, "Admin"),
    ]

    # Identification
    username = None  # Removed to use email/phone
    email = models.EmailField(unique=True, null=True, db_index=True, help_text="User's email address.")
    phone = PhoneNumberField(unique=True, null=True, db_index=True, help_text="User's phone number.")

    # Profile Data (Merged)
    avatar = models.ImageField(upload_to="avatars/%Y/%m/", default="default.jpg", help_text="User's profile picture.")
    bio = models.TextField(blank=True, help_text="User's biography.")

    # Location (Essential for Logistics)
    country = models.CharField(max_length=100, blank=True, db_index=True, help_text="User's country.")
    state = models.CharField(max_length=100, blank=True, help_text="User's state.")
    city = models.CharField(max_length=100, blank=True, help_text="User's city.")
    address = models.CharField(max_length=255, blank=True, help_text="User's address.")

    # System Fields
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default=ROLE_CLIENT, db_index=True, help_text="User's role in the system.")
    auth_provider = models.CharField(max_length=20, choices=PROVIDER_CHOICES, default=PROVIDER_EMAIL, help_text="Authentication provider used.")
    is_verified = models.BooleanField(default=False, db_index=True, help_text="Whether the user is verified.")

    # Verification Codes (From old model)
    pid = models.CharField(max_length=50, unique=True, null=True, help_text="Unique identifier.")

    groups = models.ManyToManyField(
        'auth.Group',
        verbose_name='groups',
        blank=True,
        help_text='The groups this user belongs to.',
        related_name='authentication_user_set',
        related_query_name='user',
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        verbose_name='user permissions',
        blank=True,
        help_text='Specific permissions for this user.',
        related_name='authentication_user_set',
        related_query_name='user',
    )

    class Meta:
        verbose_name = "Unified User"
        verbose_name_plural = "Unified Users"
        indexes = [
            models.Index(fields=['email', 'role']),
            models.Index(fields=['phone', 'role']),
        ]

    def __str__(self):
        return self.email if self.email else str(self.phone)

    def save(self, *args, **kwargs):
        """
        Override save to add validation and logging.
        """
        try:
            self.full_clean()  # Validate before save
            super().save(*args, **kwargs)
            logger.info(f"Saved UnifiedUser {self.pk}")
        except Exception as e:
            logger.error(f"Error saving UnifiedUser: {str(e)}")
            raise

    def is_owner(self, user):
        """
        Check if the user is the owner of this record.
        """
        return self.pk == user.pk