"""
Auth API Views Package

Synchronous (sync_views.py) and Asynchronous (async_views.py) authentication endpoints.

Views:
    - LoginView / AsyncLoginView: User login with email/phone + password
    - RegisterView / AsyncRegisterView: User registration with OTP verification
    - LogoutView / AsyncLogoutView: Token blacklisting and logout
    - RefreshTokenView / AsyncRefreshTokenView: JWT token refresh

All views follow the same patterns:
    ✅ Comprehensive docstrings (100+ lines each)
    ✅ Full error handling with logging
    ✅ Rate limiting (BurstRateThrottle)
    ✅ Standardized JSON responses ({success, message, data, errors})
    ✅ Audit trails with IP extraction
"""
