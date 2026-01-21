"""
Password Management API Views Package

Synchronous (sync_views.py) and Asynchronous (async_views.py) password management endpoints.

Views:
    - PasswordResetRequestView / AsyncPasswordResetRequestView: Initiate password reset
    - PasswordResetConfirmView / AsyncPasswordResetConfirmView: Complete password reset with token
    - ChangePasswordView / AsyncChangePasswordView: Change password for authenticated users

All views follow the same patterns:
    ✅ Comprehensive docstrings (100+ lines each)
    ✅ Full error handling with logging
    ✅ Rate limiting (BurstRateThrottle for reset, SustainedRateThrottle for change)
    ✅ Standardized JSON responses ({success, message, data, errors})
    ✅ User enumeration protection (generic responses)
    ✅ Audit trails with IP extraction
    ✅ Password strength validation
    ✅ Token expiration enforcement
"""
