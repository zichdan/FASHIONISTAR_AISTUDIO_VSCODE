# apps/authentication/apis/password_views.py
"""
Industrial-Grade Password Management API Views.

STRICT SEPARATION between Sync and Async implementations.

Endpoints:
    1. PASSWORD RESET REQUEST
       POST /api/v1/auth/password-reset/request/
       - User provides email or phone
       - System generates reset token (email) or OTP (SMS)
       - Token valid for 1 hour, OTP valid for 5 minutes

    2. PASSWORD RESET CONFIRM
       POST /api/v1/auth/password-reset/confirm/
       - User provides token/OTP + new password
       - System validates, updates password, logs event

    3. CHANGE PASSWORD (Authenticated)
       POST /api/v1/auth/password/change/
       - User provides old password + new password
       - System validates old password, updates, logs event

Security:
    ✅ Rate limiting (10/min for anonymous, 1000/day for authenticated)
    ✅ Password strength validation (8+, mixed case, digit)
    ✅ Token validation (1 hour TTL)
    ✅ OTP validation (5 min TTL)
    ✅ Audit logging (IP, user, timestamp)
    ✅ Email notification on reset success

Performance:
    - Async path: Non-blocking token generation
    - Sync path: Standard DRF, admin-compatible
"""

import logging
from typing import Dict, Any
from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str

# Async DRF imports
try:
    from drf_async.viewsets import AsyncAPIView
    ADRF_AVAILABLE = True
except ImportError:
    ADRF_AVAILABLE = False
    AsyncAPIView = None

from apps.authentication.throttles import BurstRateThrottle, SustainedRateThrottle
from apps.authentication.services.password_service import PasswordService

logger = logging.getLogger('application')
User = get_user_model()


# ============================================================================
# SYNC VIEWS (DRF - Backward Compatible)
# ============================================================================

class PasswordResetRequestView(generics.GenericAPIView):
    """
    Synchronous Password Reset Request Endpoint.

    HTTP Method: POST
    Endpoint: /api/v1/auth/password-reset/request/
    Permission: Anonymous
    Throttle: BurstRateThrottle (10/min)

    Request Body:
        {
            "email_or_phone": "user@example.com or +1234567890"
        }

    Response (200 OK):
        {
            "success": true,
            "message": "Password reset email sent. Check your inbox.",
            "data": null,
            "errors": null
        }

    Response (404 Not Found):
        {
            "success": false,
            "message": "User not found.",
            "data": null,
            "errors": null
        }

    Security:
        ✅ Rate limiting (10/min to prevent email bombing)
        ✅ Generic message (doesn't reveal if email exists)
        ✅ Token valid for 1 hour
        ✅ Token tied to user UID and email
    """

    permission_classes = [AllowAny]
    throttle_classes = [BurstRateThrottle]

    def post(self, request, *args, **kwargs):
        """
        Handle POST request for password reset request.

        Steps:
        1. Extract email/phone
        2. Find user
        3. Generate reset token
        4. Send email/SMS with reset link
        5. Return success message

        Args:
            request: HTTP request.

        Returns:
            Response: 200 OK (always for security).
        """
        try:
            email_or_phone = request.data.get('email_or_phone', '').strip()

            if not email_or_phone:
                logger.warning("[SYNC] Password reset request: Missing email/phone")
                return Response(
                    {
                        'success': False,
                        'message': 'Email or phone number is required.',
                        'data': None,
                        'errors': None
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )

            try:
                PasswordService.request_password_reset_sync(email_or_phone, request)
                logger.info(f"[SYNC] Password reset requested for {email_or_phone}")

                return Response(
                    {
                        'success': True,
                        'message': 'If the account exists, a password reset email has been sent.',
                        'data': None,
                        'errors': None
                    },
                    status=status.HTTP_200_OK
                )

            except Exception as service_err:
                logger.error(f"[SYNC] Password reset service error: {str(service_err)}")
                # Return generic message for security
                return Response(
                    {
                        'success': True,
                        'message': 'If the account exists, a password reset email has been sent.',
                        'data': None,
                        'errors': None
                    },
                    status=status.HTTP_200_OK
                )

        except Exception as e:
            logger.error(f"[SYNC] PasswordResetRequestView error: {str(e)}", exc_info=True)
            return Response(
                {
                    'success': False,
                    'message': 'An unexpected error occurred.',
                    'data': None,
                    'errors': None
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class PasswordResetConfirmView(generics.GenericAPIView):
    """
    Synchronous Password Reset Confirmation Endpoint.

    HTTP Method: POST
    Endpoint: /api/v1/auth/password-reset/confirm/
    Permission: Anonymous
    Throttle: BurstRateThrottle (10/min)

    Request Body:
        {
            "uidb64": "MQ==",
            "token": "abcd1234...",
            "new_password": "NewSecurePassword123"
        }

    Response (200 OK):
        {
            "success": true,
            "message": "Password reset successful. You can now login.",
            "data": null,
            "errors": null
        }

    Response (400 Bad Request):
        {
            "success": false,
            "message": "Invalid or expired reset token.",
            "data": null,
            "errors": null
        }

    Security:
        ✅ Token validation (1 hour TTL)
        ✅ Password strength validation
        ✅ One-time use (token consumed after use)
        ✅ Audit logging
    """

    permission_classes = [AllowAny]
    throttle_classes = [BurstRateThrottle]

    def post(self, request, *args, **kwargs):
        """
        Handle POST request for password reset confirmation.

        Steps:
        1. Extract uidb64, token, new password
        2. Validate token
        3. Validate password strength
        4. Update password
        5. Log event
        6. Return success

        Args:
            request: HTTP request.

        Returns:
            Response: 200 OK or 400 Bad Request.
        """
        try:
            uidb64 = request.data.get('uidb64', '').strip()
            token = request.data.get('token', '').strip()
            new_password = request.data.get('new_password', '').strip()

            if not all([uidb64, token, new_password]):
                return Response(
                    {
                        'success': False,
                        'message': 'All fields are required.',
                        'data': None,
                        'errors': None
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )

            try:
                PasswordService.confirm_password_reset_sync(uidb64, token, new_password, request)
                logger.info("[SYNC] Password reset completed successfully")

                return Response(
                    {
                        'success': True,
                        'message': 'Password reset successful. You can now login with your new password.',
                        'data': None,
                        'errors': None
                    },
                    status=status.HTTP_200_OK
                )

            except ValueError as ve:
                logger.warning(f"[SYNC] Password reset validation error: {str(ve)}")
                return Response(
                    {
                        'success': False,
                        'message': str(ve),
                        'data': None,
                        'errors': None
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )

            except Exception as service_err:
                logger.error(f"[SYNC] Password reset service error: {str(service_err)}")
                return Response(
                    {
                        'success': False,
                        'message': 'Password reset failed. Please try again.',
                        'data': None,
                        'errors': None
                    },
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

        except Exception as e:
            logger.error(f"[SYNC] PasswordResetConfirmView error: {str(e)}", exc_info=True)
            return Response(
                {
                    'success': False,
                    'message': 'An unexpected error occurred.',
                    'data': None,
                    'errors': None
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class ChangePasswordView(generics.GenericAPIView):
    """
    Synchronous Change Password Endpoint (Authenticated).

    HTTP Method: POST
    Endpoint: /api/v1/auth/password/change/
    Permission: Authenticated (IsAuthenticated)
    Throttle: SustainedRateThrottle (1000/day)

    Request Body:
        {
            "old_password": "CurrentPassword123",
            "new_password": "NewPassword456"
        }

    Response (200 OK):
        {
            "success": true,
            "message": "Password changed successfully.",
            "data": null,
            "errors": null
        }

    Response (401 Unauthorized):
        {
            "success": false,
            "message": "Current password is incorrect.",
            "data": null,
            "errors": null
        }

    Security:
        ✅ Requires authentication
        ✅ Old password must be verified
        ✅ New password validated for strength
        ✅ Audit logging (IP, user, timestamp)
        ✅ All other sessions invalidated (optional: logout all)
    """

    permission_classes = [IsAuthenticated]
    throttle_classes = [SustainedRateThrottle]

    def post(self, request, *args, **kwargs):
        """
        Handle POST request for password change.

        Steps:
        1. Extract old & new passwords
        2. Verify old password
        3. Validate new password strength
        4. Update password
        5. Optionally invalidate all sessions
        6. Log event
        7. Return success

        Args:
            request: HTTP request (authenticated user).

        Returns:
            Response: 200 OK or 401 Unauthorized.
        """
        try:
            old_password = request.data.get('old_password', '').strip()
            new_password = request.data.get('new_password', '').strip()

            if not old_password or not new_password:
                return Response(
                    {
                        'success': False,
                        'message': 'Old password and new password are required.',
                        'data': None,
                        'errors': None
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )

            try:
                PasswordService.change_password_sync(request.user, old_password, new_password, request)
                logger.info(f"[SYNC] Password changed for user {request.user.id}")

                return Response(
                    {
                        'success': True,
                        'message': 'Password changed successfully. Please login again.',
                        'data': None,
                        'errors': None
                    },
                    status=status.HTTP_200_OK
                )

            except ValueError as ve:
                logger.warning(f"[SYNC] Password change validation error: {str(ve)}")
                return Response(
                    {
                        'success': False,
                        'message': str(ve),
                        'data': None,
                        'errors': None
                    },
                    status=status.HTTP_401_UNAUTHORIZED
                )

            except Exception as service_err:
                logger.error(f"[SYNC] Password change service error: {str(service_err)}")
                return Response(
                    {
                        'success': False,
                        'message': 'Password change failed. Please try again.',
                        'data': None,
                        'errors': None
                    },
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

        except Exception as e:
            logger.error(f"[SYNC] ChangePasswordView error: {str(e)}", exc_info=True)
            return Response(
                {
                    'success': False,
                    'message': 'An unexpected error occurred.',
                    'data': None,
                    'errors': None
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


# ============================================================================
# ASYNC VIEWS (ADRF - Production-Grade Concurrency)
# ============================================================================

if ADRF_AVAILABLE and AsyncAPIView is not None:

    class AsyncPasswordResetRequestView(AsyncAPIView):
        """Asynchronous Password Reset Request Endpoint (Production)."""

        permission_classes = [AllowAny]
        throttle_classes = [BurstRateThrottle]

        async def post(self, request, *args, **kwargs):
            """Handle async POST request for password reset request."""
            try:
                email_or_phone = request.data.get('email_or_phone', '').strip()

                if not email_or_phone:
                    return Response(
                        {
                            'success': False,
                            'message': 'Email or phone number is required.',
                            'data': None,
                            'errors': None
                        },
                        status=status.HTTP_400_BAD_REQUEST
                    )

                try:
                    await PasswordService.request_password_reset_async(email_or_phone, request)
                    logger.info(f"[ASYNC] Password reset requested for {email_or_phone}")

                    return Response(
                        {
                            'success': True,
                            'message': 'If the account exists, a password reset email has been sent.',
                            'data': None,
                            'errors': None
                        },
                        status=status.HTTP_200_OK
                    )

                except Exception as service_err:
                    logger.error(f"[ASYNC] Password reset service error: {str(service_err)}")
                    return Response(
                        {
                            'success': True,
                            'message': 'If the account exists, a password reset email has been sent.',
                            'data': None,
                            'errors': None
                        },
                        status=status.HTTP_200_OK
                    )

            except Exception as e:
                logger.error(f"[ASYNC] AsyncPasswordResetRequestView error: {str(e)}", exc_info=True)
                return Response(
                    {
                        'success': False,
                        'message': 'An unexpected error occurred.',
                        'data': None,
                        'errors': None
                    },
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

    class AsyncPasswordResetConfirmView(AsyncAPIView):
        """Asynchronous Password Reset Confirmation Endpoint (Production)."""

        permission_classes = [AllowAny]
        throttle_classes = [BurstRateThrottle]

        async def post(self, request, *args, **kwargs):
            """Handle async POST request for password reset confirmation."""
            try:
                uidb64 = request.data.get('uidb64', '').strip()
                token = request.data.get('token', '').strip()
                new_password = request.data.get('new_password', '').strip()

                if not all([uidb64, token, new_password]):
                    return Response(
                        {
                            'success': False,
                            'message': 'All fields are required.',
                            'data': None,
                            'errors': None
                        },
                        status=status.HTTP_400_BAD_REQUEST
                    )

                try:
                    await PasswordService.confirm_password_reset_async(uidb64, token, new_password, request)
                    logger.info("[ASYNC] Password reset completed successfully")

                    return Response(
                        {
                            'success': True,
                            'message': 'Password reset successful. You can now login with your new password.',
                            'data': None,
                            'errors': None
                        },
                        status=status.HTTP_200_OK
                    )

                except ValueError as ve:
                    logger.warning(f"[ASYNC] Password reset validation error: {str(ve)}")
                    return Response(
                        {
                            'success': False,
                            'message': str(ve),
                            'data': None,
                            'errors': None
                        },
                        status=status.HTTP_400_BAD_REQUEST
                    )

                except Exception as service_err:
                    logger.error(f"[ASYNC] Password reset service error: {str(service_err)}")
                    return Response(
                        {
                            'success': False,
                            'message': 'Password reset failed. Please try again.',
                            'data': None,
                            'errors': None
                        },
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR
                    )

            except Exception as e:
                logger.error(f"[ASYNC] AsyncPasswordResetConfirmView error: {str(e)}", exc_info=True)
                return Response(
                    {
                        'success': False,
                        'message': 'An unexpected error occurred.',
                        'data': None,
                        'errors': None
                    },
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

    class AsyncChangePasswordView(AsyncAPIView):
        """Asynchronous Change Password Endpoint (Production)."""

        permission_classes = [IsAuthenticated]
        throttle_classes = [SustainedRateThrottle]

        async def post(self, request, *args, **kwargs):
            """Handle async POST request for password change."""
            try:
                old_password = request.data.get('old_password', '').strip()
                new_password = request.data.get('new_password', '').strip()

                if not old_password or not new_password:
                    return Response(
                        {
                            'success': False,
                            'message': 'Old password and new password are required.',
                            'data': None,
                            'errors': None
                        },
                        status=status.HTTP_400_BAD_REQUEST
                    )

                try:
                    await PasswordService.change_password_async(request.user, old_password, new_password, request)
                    logger.info(f"[ASYNC] Password changed for user {request.user.id}")

                    return Response(
                        {
                            'success': True,
                            'message': 'Password changed successfully. Please login again.',
                            'data': None,
                            'errors': None
                        },
                        status=status.HTTP_200_OK
                    )

                except ValueError as ve:
                    logger.warning(f"[ASYNC] Password change validation error: {str(ve)}")
                    return Response(
                        {
                            'success': False,
                            'message': str(ve),
                            'data': None,
                            'errors': None
                        },
                        status=status.HTTP_401_UNAUTHORIZED
                    )

                except Exception as service_err:
                    logger.error(f"[ASYNC] Password change service error: {str(service_err)}")
                    return Response(
                        {
                            'success': False,
                            'message': 'Password change failed. Please try again.',
                            'data': None,
                            'errors': None
                        },
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR
                    )

            except Exception as e:
                logger.error(f"[ASYNC] AsyncChangePasswordView error: {str(e)}", exc_info=True)
                return Response(
                    {
                        'success': False,
                        'message': 'An unexpected error occurred.',
                        'data': None,
                        'errors': None
                    },
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

else:
    logger.warning("ADRF not available. Async password views disabled.")