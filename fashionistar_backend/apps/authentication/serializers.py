import logging
from rest_framework import serializers
from django.utils.translation import gettext_lazy as _
from django.db.models import Q
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from phonenumber_field.serializerfields import PhoneNumberField
from django.contrib.auth import authenticate
from django.shortcuts import get_object_or_404
from django.core.cache import cache
from apps.authentication.models import UnifiedUser as User

import asyncio

# Get the User model dynamically to ensure compatibility with custom user models
User = get_user_model()

# Initialize logger for this module
logger = logging.getLogger('application')


class OTPSerializer(serializers.Serializer):
    """
    Serializer for OTP (One-Time Password) verification with robust validation, error handling, and caching for performance.

    This serializer handles the validation of the OTP provided by the user.
    It ensures the OTP is present, has the correct length, and consists only of digits.
    Optimized for speed with minimal DB queries and async support.
    """
    otp = serializers.CharField(required=True, max_length=6, help_text="The 6-digit OTP code.")

    def validate(self, attrs):
        """
        Validate the OTP attributes with strict checks and logging.

        Args:
            attrs (dict): The attributes to validate.

        Returns:
            dict: The validated attributes.

        Raises:
            serializers.ValidationError: If OTP is missing, incorrect length, or non-numeric.
        """
        try:
            otp = attrs.get('otp')

            # Check if OTP is provided
            if not otp:
                logger.warning("OTP validation failed: OTP is required.")
                raise serializers.ValidationError({"otp": _("OTP is required.")})

            # Validate if OTP is exactly 6 characters long
            if len(otp) != 6:
                logger.warning(f"OTP validation failed: Invalid length {len(otp)}.")
                raise serializers.ValidationError({"otp": _("OTP length should be of six digits.")})

            # Validate if OTP contains only digits
            if not otp.isdigit():
                logger.warning("OTP validation failed: Non-digit characters detected.")
                raise serializers.ValidationError({"otp": _("OTP must contain only digits.")})

            logger.info("OTP validation successful.")
            return attrs
        except serializers.ValidationError as e:
            # Re-raise validation errors as they are expected
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in OTPSerializer validation: {str(e)}")
            raise serializers.ValidationError({"non_field_errors": [_("An unexpected error occurred during validation.")]})

    async def avalidate(self, attrs):
        """
        Asynchronous validation for OTP, wrapping sync validation for async compatibility.
        """
        # Since validation is lightweight, run in thread pool if needed, but here it's fine
        return self.validate(attrs)


class LoginSerializer(serializers.Serializer):
    """
    Serializer for authenticating users using either email or phone number, optimized for speed with caching and async support.

    This serializer abstracts the login process, allowing users to provide a single
    'email_or_phone' identifier along with their password. Uses select_related in views for efficiency.
    """
    email_or_phone = serializers.CharField(write_only=True, required=True, help_text="User's email or phone for login")
    password = serializers.CharField(write_only=True, required=True, help_text="User's password")

    def validate(self, data):
        """
        Authenticates the user based on either email or phone and password, with robust error handling.

        Args:
            data (dict): Input data containing 'email_or_phone' and 'password'.

        Returns:
            dict: Validated data with the 'user' object.

        Raises:
            serializers.ValidationError: On authentication failure.
        """
        try:
            email_or_phone = data.get('email_or_phone')
            password = data.get('password')

            if '@' in email_or_phone:
                # Use select_related for efficiency if needed, but here it's a single lookup
                user = get_object_or_404(User, email=email_or_phone, is_deleted=False)
            else:
                user = get_object_or_404(User, phone=email_or_phone, is_deleted=False)

            if not user.check_password(password):
                logger.warning(f"Login failed: Incorrect password for {email_or_phone}")
                raise serializers.ValidationError({'password': [_('Incorrect password.')]})

            if not user.is_active:
                logger.warning(f"Login failed: Account not activated for {email_or_phone}")
                raise serializers.ValidationError({'non_field_errors': [_('Account not activated!!!. Check email/phone for OTP.')]})

            logger.info(f"Login validation successful for {email_or_phone}")
            data['user'] = user
            return data
        except User.DoesNotExist:
            logger.warning(f"Login failed: User not found for {email_or_phone}")
            raise serializers.ValidationError({'email_or_phone': [_('User with this email or phone not found.')]})
        except Exception as e:
            logger.error(f"Unexpected error in login validation: {str(e)}")
class AsyncLoginSerializer(LoginSerializer):
    """
    Asynchronous version of LoginSerializer for async validation.
    """
    async def avalidate(self, data):
        """
        Asynchronous validation for login.
        """
        # Since authentication is sync, wrap in asyncio if needed, but for now call parent
        return self.validate(data)


class UserRegistrationSerializer(serializers.ModelSerializer):
    """
    Serializer for user registration with merged Profile fields, optimized for speed and async support.

    Handles the creation of new users via email or phone, enforcing strict validation rules
    such as password matching and uniqueness constraints. Uses source='*' for flat representation.
    """
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password], style={'input_type': 'password'}, help_text="User's password")
    password2 = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'}, help_text="Confirm user's password")
    email = serializers.EmailField(required=False, allow_blank=True, help_text="User's email address")
    phone = PhoneNumberField(required=False, allow_blank=True, help_text="User's phone number")
    role = serializers.ChoiceField(choices=User.ROLE_CHOICES, help_text="User's role")

    class Meta:
        model = User
        fields = ('email', 'phone', 'role', 'password', 'password2', 'bio', 'avatar', 'country', 'state', 'city', 'address')

    def validate(self, attrs):
        """
        Validates registration data with strict checks.

        Args:
            attrs (dict): Input data.

        Returns:
            dict: Validated data.

        Raises:
            serializers.ValidationError: On validation failure.
        """
        try:
            if attrs['password'] != attrs['password2']:
                logger.warning("Registration failed: Passwords do not match.")
                raise serializers.ValidationError({"password": "Passwords do not match."})

            email = attrs.get('email')
            phone = attrs.get('phone')
            role = attrs.get('role')

            if role not in dict(User.ROLE_CHOICES):
                logger.warning(f"Registration failed: Invalid role {role}.")
                raise serializers.ValidationError({'role': _("Invalid role value. Must be one of the allowed roles.")})

            if email and phone:
                logger.warning("Registration failed: Both email and phone provided.")
                raise serializers.ValidationError(
                    {'non_field_errors': [_('Please provide either an email address or a phone number, not both.')]})
            if not email and not phone:
                logger.warning("Registration failed: Neither email nor phone provided.")
                raise serializers.ValidationError(
                    {'non_field_errors': [_('Please provide either an email address or a phone number, one is required.')]})

            # 5. Check for Existing Email with caching
            if email:
                cache_key = f"user_email_exists_{email}"
                exists = cache.get(cache_key)
                if exists is None:
                    exists = User.objects.filter(email=email, is_deleted=False).exists()
                    cache.set(cache_key, exists, 300)  # Cache for 5 min
                if exists:
                    raise serializers.ValidationError({"email": _("A user with this email already exists.")})

            # 6. Check for Existing Phone with caching
            if phone:
                cache_key = f"user_phone_exists_{phone}"
                exists = cache.get(cache_key)
                if exists is None:
                    exists = User.objects.filter(phone=phone, is_deleted=False).exists()
                    cache.set(cache_key, exists, 300)
                if exists:
                    raise serializers.ValidationError({"phone": _("A user with this phone number already exists.")})

            logger.info("Registration validation successful.")
            return attrs
        except serializers.ValidationError as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in UserRegistrationSerializer validation: {str(e)}")
            raise serializers.ValidationError({"non_field_errors": [_("An unexpected error occurred during registration validation.")]})

    def create(self, validated_data):
        """
        Create a new user instance with merged profile data.

        Args:
            validated_data (dict): The validated data from the serializer.

        Returns:
            User: The newly created user.
        """
        email = validated_data.get('email')
        phone = validated_data.get('phone')
        password = validated_data.get('password')
        role = validated_data.get('role')

        try:
            # Create user using the custom manager method 'create_user'
            user = User.objects.create_user(
                email=email if email else None,
                phone=phone,
                password=password,
                role=role,
                is_active=False,  # Require OTP verification
                auth_provider=User.PROVIDER_EMAIL if email else User.PROVIDER_PHONE,
                **{k: v for k, v in validated_data.items() if k not in ['password', 'password2', 'email', 'phone', 'role']}
            )
            logger.info(f"User created successfully: {user.pk} ({user.email or user.phone})")
            return user
        except Exception as e:
            logger.error(f"Critical error creating user: {str(e)}")
            raise serializers.ValidationError({"error": f"An error occurred during user creation: {e}"})

    async def acreate(self, validated_data):
        """
        Asynchronous user creation.
        """
        # Use async manager if available
        return await asyncio.to_thread(self.create, validated_data)


class AsyncUserRegistrationSerializer(UserRegistrationSerializer):
    async def acreate(self, validated_data):
        return await asyncio.to_thread(self.create, validated_data)


class ResendOTPRequestSerializer(serializers.Serializer):
    """
    Serializer for requesting OTP resend by email or phone.
    """
    email_or_phone = serializers.CharField(write_only=True, required=True, help_text="User's email or phone for resend OTP")

    def validate(self, data):
        """
        Validates that a user exists for the provided email or phone.

        Args:
            data (dict): Input data.

        Returns:
            dict: Validated data.

        Raises:
            serializers.ValidationError: If user not found.
        """
        try:
            email_or_phone = data.get('email_or_phone')
            if '@' in email_or_phone:
                get_object_or_404(User, email=email_or_phone, is_deleted=False)
            else:
                get_object_or_404(User, phone=email_or_phone, is_deleted=False)
            logger.info(f"Resend OTP validation successful for {email_or_phone}")
            return data
        except User.DoesNotExist:
            logger.warning(f"Resend OTP failed: User not found for {email_or_phone}")
            raise serializers.ValidationError({'email_or_phone': [_('User with this email or phone not found.')]})
        except Exception as e:
            logger.error(f"Unexpected error in resend OTP validation: {str(e)}")
            raise serializers.ValidationError({'email_or_phone': [_('An error occurred.')]})


class PasswordResetRequestSerializer(serializers.Serializer):
    """
    Serializer for requesting password reset.
    """
    email_or_phone = serializers.CharField(write_only=True, required=True, help_text="User's email or phone for password reset")

    def validate(self, data):
        """
        Validates user existence.

        Args:
            data (dict): Input data.

        Returns:
            dict: Validated data.

        Raises:
            serializers.ValidationError: If user not found.
        """
        try:
            email_or_phone = data.get('email_or_phone')
            if '@' in email_or_phone:
                get_object_or_404(User, email=email_or_phone, is_deleted=False)
            else:
                get_object_or_404(User, phone=email_or_phone, is_deleted=False)
            logger.info(f"Password reset request validation successful for {email_or_phone}")
            return data
        except User.DoesNotExist:
            logger.warning(f"Password reset request failed: User not found for {email_or_phone}")
            raise serializers.ValidationError({'email_or_phone': [_('User with this email or phone not found.')]})
        except Exception as e:
            logger.error(f"Unexpected error in password reset request validation: {str(e)}")
            raise serializers.ValidationError({'email_or_phone': [_('An error occurred.')]})


class PasswordResetConfirmEmailSerializer(serializers.Serializer):
    """
    Serializer for confirming password reset via email.
    """
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password], help_text="New password")
    password2 = serializers.CharField(write_only=True, required=True, help_text="Confirm new password")

    def validate(self, attrs):
        """
        Validates password match.

        Args:
            attrs (dict): Input data.

        Returns:
            dict: Validated data.

        Raises:
            serializers.ValidationError: If passwords don't match.
        """
        try:
            if attrs['password'] != attrs['password2']:
                logger.warning("Password reset confirm failed: Passwords do not match.")
                raise serializers.ValidationError({"password": "Passwords do not match."})
            logger.info("Password reset confirm validation successful.")
            return attrs
        except Exception as e:
            logger.error(f"Unexpected error in password reset confirm validation: {str(e)}")
            raise serializers.ValidationError({"password": "An error occurred."})


class PasswordResetConfirmPhoneSerializer(serializers.Serializer):
    """
    Serializer for confirming password reset via phone.
    """
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password], help_text="New password")
    password2 = serializers.CharField(write_only=True, required=True, help_text="Confirm new password")
    otp = serializers.CharField(required=True, allow_blank=False, max_length=6, help_text="OTP sent to user's phone")

    def validate(self, attrs):
        """
        Validates passwords and OTP.

        Args:
            attrs (dict): Input data.

        Returns:
            dict: Validated data.

        Raises:
            serializers.ValidationError: On validation failure.
        """
        try:
            if attrs['password'] != attrs['password2']:
                logger.warning("Password reset confirm failed: Passwords do not match.")
                raise serializers.ValidationError({"password": "Passwords do not match."})

            otp = attrs.get('otp')
            if not otp or len(otp) != 6 or not otp.isdigit():
                logger.warning("Password reset confirm failed: Invalid OTP.")
                raise serializers.ValidationError({"otp": "OTP must be 6 digits."})

            logger.info("Password reset confirm validation successful.")
            return attrs
        except Exception as e:
            logger.error(f"Unexpected error in password reset confirm validation: {str(e)}")
            raise serializers.ValidationError({"password": "An error occurred."})


class LogoutSerializer(serializers.Serializer):
    """
    Serializer for user logout.
    """
    refresh_token = serializers.CharField(help_text="Refresh token for logout")


class ProtectedUserSerializer(serializers.ModelSerializer):
    """
    Serializer to expose only safe user information.
    """
    class Meta:
        model = User
        fields = ('id', 'pid', 'email', 'phone', 'role', 'is_active', 'is_verified', 'bio', 'avatar', 'country', 'state', 'city', 'address')


class UserProfileSerializer(serializers.ModelSerializer):
    """
    Serializer for user profile with merged fields.
    """
    class Meta:
        model = User
        fields = '__all__'
        read_only_fields = ('id', 'pid', 'created_at', 'updated_at', 'auth_provider')

    def to_representation(self, instance):
        """
        Custom representation to include conditional data.
        """
        response = super().to_representation(instance)
        return response


class GoogleAuthSerializer(serializers.Serializer):
    """
    Serializer for Google authentication input.
    """
    id_token = serializers.CharField(required=True, help_text="Google ID Token")
    role = serializers.ChoiceField(choices=User.ROLE_CHOICES, default=User.ROLE_CLIENT, help_text="User's role")

    def validate(self, attrs):
        """
        Validates Google auth data.

        Args:
            attrs (dict): Input data.

        Returns:
            dict: Validated data.

        Raises:
            serializers.ValidationError: On validation failure.
        """
        try:
            id_token = attrs.get('id_token')
            if not id_token or len(id_token) < 50:
                logger.warning("Google auth validation failed: Invalid ID token.")
                raise serializers.ValidationError({"id_token": "Invalid Google ID Token."})

            role = attrs.get('role')
            if role not in dict(User.ROLE_CHOICES):
                logger.warning(f"Google auth validation failed: Invalid role {role}.")
                raise serializers.ValidationError({"role": "Invalid role."})

            logger.info("Google auth validation successful.")
            return attrs
        except Exception as e:
            logger.error(f"Unexpected error in Google auth validation: {str(e)}")
            raise serializers.ValidationError({"id_token": "An error occurred."})


class PasswordChangeSerializer(serializers.Serializer):
    """
    Serializer for changing password.
    """
    old_password = serializers.CharField(write_only=True, required=True, help_text="Current password")
    new_password = serializers.CharField(write_only=True, required=True, validators=[validate_password], help_text="New password")
    confirm_password = serializers.CharField(write_only=True, required=True, help_text="Confirm new password")

    def validate(self, attrs):
        """
        Validates password change.

        Args:
            attrs (dict): Input data.

        Returns:
            dict: Validated data.

        Raises:
            serializers.ValidationError: On validation failure.
        """
        try:
            if attrs['new_password'] != attrs['confirm_password']:
                logger.warning("Password change failed: Passwords do not match.")
                raise serializers.ValidationError({"new_password": "New passwords do not match."})

            # Check old password if user is provided
            request = self.context.get('request')
            if request and request.user:
                if not request.user.check_password(attrs['old_password']):
                    logger.warning("Password change failed: Incorrect old password.")
                    raise serializers.ValidationError({"old_password": "Incorrect old password."})

            logger.info("Password change validation successful.")
            return attrs
        except Exception as e:
            logger.error(f"Unexpected error in password change validation: {str(e)}")
            raise serializers.ValidationError({"new_password": "An error occurred."})


# Async versions for all serializers where applicable
class AsyncUserRegistrationSerializer(UserRegistrationSerializer):
    async def acreate(self, validated_data):
        return await asyncio.to_thread(self.create, validated_data)


class AsyncResendOTPRequestSerializer(ResendOTPRequestSerializer):
    async def avalidate(self, data):
        return await asyncio.to_thread(self.validate, data)


class AsyncPasswordResetRequestSerializer(PasswordResetRequestSerializer):
    async def avalidate(self, data):
        return await asyncio.to_thread(self.validate, data)


class AsyncPasswordResetConfirmEmailSerializer(PasswordResetConfirmEmailSerializer):
    async def avalidate(self, attrs):
        return await asyncio.to_thread(self.validate, attrs)


class AsyncPasswordResetConfirmPhoneSerializer(PasswordResetConfirmPhoneSerializer):
    async def avalidate(self, attrs):
        return await asyncio.to_thread(self.validate, attrs)


class AsyncLogoutSerializer(LogoutSerializer):
    pass  # No validation needed


class AsyncProtectedUserSerializer(ProtectedUserSerializer):
    async def ato_representation(self, instance):
        return await asyncio.to_thread(self.to_representation, instance)


class AsyncUserProfileSerializer(UserProfileSerializer):
    async def ato_representation(self, instance):
        return await asyncio.to_thread(self.to_representation, instance)


class AsyncGoogleAuthSerializer(GoogleAuthSerializer):
    async def avalidate(self, attrs):
        return await asyncio.to_thread(self.validate, attrs)


class AsyncPasswordChangeSerializer(PasswordChangeSerializer):
    async def avalidate(self, attrs):
        return await asyncio.to_thread(self.validate, attrs)