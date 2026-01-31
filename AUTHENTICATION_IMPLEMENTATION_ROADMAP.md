# AUTHENTICATION IMPLEMENTATION ROADMAP
## Complete Study & 10-Step Enterprise-Grade Implementation Plan
### Version 1.0 (Study Phase - Do Not Execute Yet)
### Date: January 31, 2026

---

## EXECUTIVE SUMMARY

This document represents a **comprehensive study and analysis** of your existing authentication system, combined with a **10-step implementation roadmap** that bridges your current `userauths` legacy application with the new `apps/authentication` and `apps/common` modules designed for Django 6.0+ async-first architecture.

**Current State Analysis:**
- Your existing `userauths` application uses DRF with Celery tasks, Redis OTP encryption, and atomic transactions
- Your new `apps/authentication` already has modern async services (auth_service.py, otp_service.py) with dual-path support
- You have custom managers (`CustomUserManager`) with both sync and async methods
- You have a unified user model (`UnifiedUser`) that merges legacy Profile data

**Target State:**
- Complete industrial-grade authentication with STRICT separation of concerns
- Parallel sync (DRF) and async (Django-Ninja/ADRF) paths for all endpoints
- Full integration with `apps/common` utilities (email, SMS, Redis, encryption)
- Comprehensive logging, error handling, and audit trails
- Production-ready security patterns

---

## PART A: EXISTING DESIGN ANALYSIS

### A.1. The Old `userauths` Architecture Pattern Study

#### A.1.1. View Layer Pattern (DRF Generics)

From your old code, the view pattern is:

```
RegisterViewCelery(generics.CreateAPIView):
    ├── permission_classes = AllowAny
    ├── serializer_class = UserRegistrationSerializer
    ├── create() override with @transaction.atomic
    │   ├── Serialize input (user registration data)
    │   ├── Save user (transaction boundary)
    │   ├── Generate OTP (sync utility function)
    │   ├── Encrypt OTP (utility function from common)
    │   ├── Store in Redis with TTL
    │   ├── Send email/SMS via Celery tasks
    │   └── Return standardized JSON response
    └── Exception handling: ValidationError, generic Exception

Key Insights:
✅ Atomic transactions ensure data consistency
✅ Celery tasks decouple I/O from the request-response cycle
✅ Redis encryption for OTP security (Fernet cipher)
✅ Comprehensive logging at each step
✅ Try-except blocks with specific error handling
```

#### A.1.2. Serializer Layer Pattern

Your serializers follow a **validation-first** approach:

```
UserRegistrationSerializer(ModelSerializer):
    ├── Validate passwords match
    ├── Validate email/phone uniqueness
    ├── Validate at least one identifier (email OR phone)
    ├── Validate role is in allowed choices
    └── Create user with encrypted password

Key Insights:
✅ Explicit field validation methods
✅ Custom validation logic (passwords, uniqueness)
✅ Integration with Django's password validators
✅ Clear error messages for frontend
✅ Support for both email and phone registration
```

#### A.1.3. OTP Flow Pattern

Your OTP implementation follows a **secure encryption + Redis storage** pattern:

```
OTP Generation Flow:
1. Generate random 6-digit OTP (cryptographically secure)
2. Encrypt OTP with Fernet cipher (AES-256 equivalent)
3. Store encrypted OTP in Redis with user_id in key
4. Set TTL (300 seconds = 5 minutes)
5. Send OTP to email/phone via Celery

OTP Verification Flow:
1. Scan Redis for matching OTP key using scan_iter
2. Decrypt stored OTP
3. Compare with provided OTP
4. Delete from Redis on successful match (one-time use)
5. Mark user as verified + active
6. Generate JWT tokens immediately

Key Insights:
✅ Direct key access pattern (otp_data:{user_id}:{encrypted_otp})
✅ Prevents timing attacks via pattern scanning
✅ One-time use prevents replay attacks
✅ TTL-based auto-cleanup
✅ Purpose-scoped keys (login, reset, verify)
```

#### A.1.4. Password Reset Pattern

Your password reset follows a **token-based + OTP hybrid** approach:

```
Email Flow:
1. Generate Django token (default_token_generator)
2. Encode user ID (urlsafe_base64_encode)
3. Store in Redis with TTL
4. Send email with reset link
5. User clicks link with uidb64 + token
6. Verify token with Django's check_token
7. User submits new password
8. Set password + save

Phone Flow:
1. Generate 6-digit OTP
2. Encrypt OTP
3. Store in Redis with TTL
4. Send OTP via SMS
5. User submits OTP + new password
6. Verify OTP against encrypted value
7. Set password + save

Key Insights:
✅ Dual-path support (email token vs SMS OTP)
✅ Redis as temporary storage (no DB writes until confirmed)
✅ User enumeration protection (returns same message for found/not found)
✅ Transaction safety with @transaction.atomic
```

#### A.1.5. Email & SMS Integration Pattern

Your old code uses **Celery tasks** for async dispatch:

```
Email Pattern:
- Use Celery signature: signature('userauths.tasks.send_email_task', args=(...))
- Apply async: email_task.apply_async()
- Template rendering: render_to_string(template_name, context)
- HTML + plaintext support

SMS Pattern:
- Use Celery: send_sms_task.delay(phone, body)
- Phone number format: as_e164 (international format)

Key Insights:
✅ Fire-and-forget pattern (don't wait for email delivery)
✅ Decouples I/O from request-response cycle
✅ Maintains audit trail (logging before dispatch)
```

---

## PART B: NEW ARCHITECTURE ANALYSIS

### B.1. The New `apps/authentication` + `apps/common` Architecture

Your new code follows **industrial-grade patterns**:

#### B.1.1. Separation of Concerns

```
apps/common/
├── models.py (TimeStampedModel, SoftDeleteModel, HardDeleteMixin, DeletedRecords)
├── utils.py (OTP encryption, Redis connection, Cloudinary deletion)
├── managers/
│   ├── email.py (EmailManager with sync + async methods)
│   └── sms.py (SMSManager with sync + async methods)
└── permissions.py (Granular role-based access)

apps/authentication/
├── models.py (UnifiedUser - merged with Profile)
├── managers.py (CustomUserManager with sync + async)
├── services/
│   ├── auth_service.py (Login/Register with dual paths)
│   ├── otp_service.py (OTP generation + verification)
│   ├── google_service.py (Google OAuth integration)
│   ├── password_service.py (Password reset logic)
│   └── registration_service.py (User creation logic)
├── serializers.py (Input validation)
├── apis/
│   ├── auth/
│   │   ├── sync_views.py (DRF views)
│   │   └── async_views.py (ADRF/async views)
│   └── password/
│       ├── sync_views.py (DRF views)
│       └── async_views.py (ADRF/async views)
├── types/
│   └── auth_schemas.py (Pydantic schemas)
└── tests/ (Comprehensive unit + integration tests)

Key Insights:
✅ Services contain business logic (no views calling views)
✅ Serializers handle input validation only
✅ Views are thin controllers (delegate to services)
✅ Managers handle ORM operations (optimized queries)
✅ Common utilities avoid code duplication
✅ Complete async/sync separation (no blocking)
```

#### B.1.2. Dual-Path Architecture Pattern

```
SYNC PATH (DRF - Backward Compatible):
LoginView(generics.GenericAPIView)
  ├── Throttle: BurstRateThrottle
  ├── Call: AuthService.login_sync(data, request)
  └── Return: standardized JSON

ASYNC PATH (ADRF/Async - High Concurrency):
AsyncLoginView(AsyncAPIView)
  ├── Throttle: BurstRateThrottle (non-blocking)
  ├── Call: await AuthService.login_async(data, request)
  └── Return: standardized JSON

Key Insights:
✅ V1 = Sync (backward compatible, WSGI-safe)
✅ V2 = Async (production-ready, ASGI, high-concurrency)
✅ NO code sharing between sync/async (prevents blocking)
✅ Same business logic, different transport
```

---

## PART C: KEY TECHNICAL PATTERNS TO PRESERVE & IMPLEMENT

### C.1. Redis OTP Storage Pattern

**PRESERVE THIS:**
```python
# Pattern from your old code:
redis_key = f"otp_data:{user_id}:{encrypted_otp}"
redis_conn.setex(redis_key, 300, str(otp_data))

# Scan for retrieval:
for key in redis_conn.scan_iter(match="otp_data:*"):
    otp_data = eval(redis_conn.get(key).decode('utf-8'))
```

**NEW APPROACH (Purpose-Scoped):**
```python
# Align with services/otp_service.py:
redis_key = f"otp:{user_id}:{purpose}:{encrypted_otp[:8]}"
# Purpose: 'login', 'reset', 'verify', 'change_password'
# Prevents cross-purpose OTP reuse
```

### C.2. Atomic Transaction Pattern

**PRESERVE THIS:**
```python
@transaction.atomic
def post(self, request):
    try:
        # User creation + Redis ops all atomic
        # If any step fails, entire transaction rolls back
        if redis_error:
            transaction.set_rollback(True)
            return error_response
    except Exception:
        transaction.set_rollback(True)
        raise
```

### C.3. Celery Task Dispatch Pattern

**TRANSITION THIS:**
```python
# OLD PATTERN (Celery):
email_task = signature('userauths.tasks.send_email_task', args=(...))
email_task.apply_async()

# NEW PATTERN (Dual-Path):
# Sync: EmailManager.send_mail(...)
# Async: await EmailManager.asend_mail(...)
# Background task (optional): Via Django 6.0 native tasks with Redis
```

### C.4. Custom User Manager Pattern

**PRESERVE THIS:**
```python
class CustomUserManager(BaseUserManager):
    def create_user(self, email=None, phone=None, password=None, **extra_fields):
        # Sync: User creation with validation
        
    async def acreate_user(self, email=None, phone=None, password=None, **extra_fields):
        # Async: Native async user creation
```

### C.5. Encryption Pattern

**PRESERVE THIS:**
```python
# From apps/common/utils.py:
cipher_suite = Fernet(base64.urlsafe_b64encode(SECRET_KEY[:32]))

def encrypt_otp(otp):
    return cipher_suite.encrypt(otp.encode()).decode()

def decrypt_otp(encrypted_otp):
    return cipher_suite.decrypt(encrypted_otp.encode()).decode()
```

---

## PART D: ARCHITECTURAL DECISIONS & TRADE-OFFS

### D.1. Why Sync + Async (Dual-Path)?

| Decision | Reason | Trade-off |
|----------|--------|-----------|
| **Keep DRF (v1)** | Backward compatible, simpler to debug, traditional WSGI servers | Slower under high concurrency (thread overhead) |
| **Add ADRF (v2)** | Native async, handles 1000s concurrent, non-blocking I/O | Requires ASGI server, slight complexity increase |
| **Same Business Logic** | DRY principle, reduce maintenance | Need strict async/sync separation in services |

### D.2. Why Services > Views > Serializers?

```
Request Flow:
1. View receives HTTP request
2. View validates with Serializer (lightweight)
3. View calls Service method
4. Service contains ALL business logic
5. Service returns plain Python object/dict
6. View formats response + returns

Benefits:
✅ Services are testable (no HTTP/request context)
✅ Services are reusable (views + Celery tasks + CLI)
✅ Views stay thin (easier to debug)
✅ Separation of concerns (validation != business logic)
```

### D.3. Why Redis for OTP, Not Database?

```
| Approach | Write Latency | Query Speed | TTL Support | Transaction Safe | Use Case |
|----------|---------------|-------------|-------------|------------------|----------|
| Database | ~100ms | ~50ms | Manual cleanup | ✅ Native | Audit trail |
| Redis | ~1ms | ~0.1ms | ✅ Native | ⚠️ Eventual | High-frequency |

Choice: Redis for OTP
✅ 100x faster than database
✅ TTL-based auto-cleanup (no bloat)
✅ Perfect for short-lived tokens (5 min)
✅ Can scale to millions of concurrent OTPs
```

### D.4. Why Unified User Model?

```
OLD PATTERN (Profile + User):
User (auth-focused) → Profile (data-focused) [OneToOne link]
- Problem: N+1 queries (every user lookup requires profile fetch)
- Problem: Data model confusion
- Problem: Soft-delete requires two cascades

NEW PATTERN (UnifiedUser):
UnifiedUser (everything in one model)
- Benefit: Single query for all user data
- Benefit: Atomic operations (one transaction)
- Benefit: Soft-delete works on single model
```

---

## PART E: INTEGRATION POINTS ANALYSIS

### E.1. Apps to Integrate With

```
1. apps/common
   ├── utils.py (OTP encryption, Redis, Cloudinary)
   ├── models.py (TimeStampedModel, SoftDeleteModel)
   ├── managers/
   │   ├── email.py (EmailManager.send_mail / asend_mail)
   │   └── sms.py (SMSManager.send_sms / asend_sms)
   └── permissions.py (IsVendor, IsClient, IsStaff, etc.)

2. apps/authentication
   ├── models.py (UnifiedUser model)
   ├── managers.py (CustomUserManager)
   ├── services/ (Business logic)
   └── serializers.py (Input validation)

3. External Services
   ├── Email Backend (Mailgun/Zoho via admin_backend)
   ├── SMS Backend (Twilio/BulkSMS/Termii via admin_backend)
   └── Google OAuth (id_token verification)
```

### E.2. Settings Configuration Required

```python
# backend/settings.py should already have:

# Redis
REDIS_URL = env('REDIS_URL', 'redis://localhost:6379/0')

# OTP Encryption
SECRET_KEY = env('SECRET_KEY')  # Used for Fernet cipher

# Email Backend
EMAIL_BACKEND = 'admin_backend.backends.email_backends.DatabaseConfiguredEmailBackend'
DEFAULT_FROM_EMAIL = env('DEFAULT_FROM_EMAIL')

# SMS Backend
SMS_BACKEND = 'admin_backend.backends.sms_backends.DatabaseConfiguredSMSBackend'

# JWT Settings
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=5),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=30),
}

# Logging
LOGGING = {
    'loggers': {
        'application': {'level': 'INFO'},
    }
}
```

---

## PART F: 10-STEP IMPLEMENTATION ROADMAP

### **SEGMENT 1: REGISTRATION (SYNC & ASYNC)**

#### **STEP 1: Implement Registration Service (Both Sync & Async)**

**Purpose:** Core registration logic with user creation, OTP generation, and email/SMS dispatch.

**Location:** `apps/authentication/services/registration_service.py`

**Dependencies:**
- `apps/authentication/managers.py` (CustomUserManager)
- `apps/authentication/services/otp_service.py` (OTPService)
- `apps/common/managers/email.py` (EmailManager)
- `apps/common/managers/sms.py` (SMSManager)
- `apps/common/utils.py` (get_otp_expiry_datetime, etc.)

**Procedure:**

```
A. SYNC PATH (RegistrationService.register_sync)
   └─ Accepts: email/phone, password, role, auth_provider
      1. Create user via CustomUserManager.create_user()
      2. User created with is_active=False, is_verified=False
      3. Log: "User {email_or_phone} registration initiated"
      4. Generate OTP via OTPService.generate_otp_sync()
      5. Determine channel (email vs phone)
         ├─ Email: Compose email context, call EmailManager.send_mail()
         └─ Phone: Compose SMS body, call SMSManager.send_sms()
      6. Return: {"message": "Check email/phone for OTP", "user_id": user.id}
      7. Exception handling: ValidationError, Exception
         └─ Log error, raise with user-friendly message

B. ASYNC PATH (RegistrationService.register_async)
   └─ Accepts: same as sync path
      1. Create user via CustomUserManager.acreate_user() [async]
      2. Log: "User {email_or_phone} registration initiated [ASYNC]"
      3. Generate OTP via OTPService.generate_otp_async() [async]
      4. Determine channel
         ├─ Email: await EmailManager.asend_mail() [async]
         └─ Phone: await SMSManager.asend_sms() [async]
      5. Return: same response
      6. Exception handling: same pattern

C. INTEGRATION POINTS
   ├─ Custom Email/SMS Backends (from admin_backend):
   │  └─ EmailManager/SMSManager call admin-configured providers
   ├─ Redis OTP Storage:
   │  └─ OTPService uses get_redis_connection_safe()
   └─ Logging:
      └─ Every step logged with user_id, action, timestamp, IP
```

**Code Structure Example:**
```python
class RegistrationService:
    """
    Handles user registration with comprehensive error handling,
    logging, and support for both sync and async paths.
    """

    @staticmethod
    def register_sync(email: str = None, phone: str = None, 
                     password: str = None, role: str = 'client',
                     request=None) -> Dict[str, Any]:
        """
        Synchronous user registration flow.
        
        Steps:
        1. Validate inputs (email XOR phone)
        2. Create user with CustomUserManager.create_user()
        3. Generate OTP with OTPService.generate_otp_sync()
        4. Send email/SMS via EmailManager/SMSManager
        5. Return response
        """
        try:
            # Atomic transaction boundary
            with transaction.atomic():
                # 1. Create user
                user = CustomUserManager().create_user(
                    email=email, phone=phone, 
                    password=password, role=role,
                    is_active=False, is_verified=False
                )
                logger.info(f"✅ User created: {email or phone}")
                
                # 2. Generate OTP
                otp = OTPService.generate_otp_sync(user.id, purpose='verify')
                logger.info(f"✅ OTP generated for user {user.id}")
                
                # 3. Send via email/phone
                if email:
                    context = {'user_id': user.id, 'otp': otp}
                    EmailManager.send_mail(
                        subject="Verify Your Email",
                        recipients=[email],
                        template_name='otp.html',
                        context=context
                    )
                    logger.info(f"✅ OTP email sent to {email}")
                else:
                    body = f"Your verification OTP: {otp}"
                    SMSManager.send_sms(str(phone), body)
                    logger.info(f"✅ OTP SMS sent to {phone}")
                
                return {
                    'message': 'Check email/phone for OTP',
                    'user_id': user.id
                }
        except Exception as e:
            logger.error(f"❌ Registration failed: {str(e)}", exc_info=True)
            raise RegistrationException(f"Registration failed: {str(e)}")

    @staticmethod
    async def register_async(email: str = None, phone: str = None,
                            password: str = None, role: str = 'client',
                            request=None) -> Dict[str, Any]:
        """
        Asynchronous user registration flow (Django 6.0+ native async).
        
        Uses await for all I/O operations (DB, email, SMS, Redis).
        Non-blocking throughout.
        """
        try:
            async with transaction.atomic():  # Async atomic
                # 1. Create user [async]
                user = await CustomUserManager().acreate_user(
                    email=email, phone=phone,
                    password=password, role=role,
                    is_active=False, is_verified=False
                )
                logger.info(f"✅ User created [ASYNC]: {email or phone}")
                
                # 2. Generate OTP [async]
                otp = await OTPService.generate_otp_async(user.id, purpose='verify')
                logger.info(f"✅ OTP generated [ASYNC] for user {user.id}")
                
                # 3. Send via email/phone [async]
                if email:
                    context = {'user_id': user.id, 'otp': otp}
                    await EmailManager.asend_mail(
                        subject="Verify Your Email",
                        recipients=[email],
                        template_name='otp.html',
                        context=context
                    )
                    logger.info(f"✅ OTP email sent [ASYNC] to {email}")
                else:
                    body = f"Your verification OTP: {otp}"
                    await SMSManager.asend_sms(str(phone), body)
                    logger.info(f"✅ OTP SMS sent [ASYNC] to {phone}")
                
                return {
                    'message': 'Check email/phone for OTP',
                    'user_id': user.id
                }
        except Exception as e:
            logger.error(f"❌ Registration failed [ASYNC]: {str(e)}", exc_info=True)
            raise RegistrationException(f"Registration failed: {str(e)}")
```

**Validation Points:**
```
✅ Input validation (email XOR phone, password strength)
✅ Unique constraint checking (email/phone uniqueness)
✅ Role validation (vendor/client/staff/admin)
✅ Redis connection before OTP generation
✅ Email/SMS backend availability
✅ Transaction rollback on any error
```

**Logging Points:**
```
INFO: User registration initiated (email/phone, role, auth_provider)
INFO: OTP generated (user_id, purpose, ttl)
INFO: Email sent (to, subject, timestamp)
INFO: SMS sent (to, body_preview, timestamp)
WARNING: User already exists (email/phone)
WARNING: Redis unavailable (with retry info)
ERROR: Registration failed (exception details, stack trace)
```

---

#### **STEP 2: Implement Registration Serializer & Validation**

**Purpose:** Validate registration input from HTTP request with strict rules.

**Location:** `apps/authentication/serializers.py` (extend existing)

**Dependencies:**
- Django REST Framework serializers
- Phone number field validator
- Password validators

**Procedure:**

```
A. SERIALIZER VALIDATION
   1. Validate password fields
      ├─ Check passwords match (password == password2)
      ├─ Check password strength (Django validators)
      └─ Reject if both or neither email/phone
   2. Validate identifier (email XOR phone, NOT both)
   3. Validate email format (if provided)
   4. Validate phone format (if provided, E.164)
   5. Check uniqueness (email/phone not already registered)
   6. Check role is in allowed choices

B. ERROR MESSAGES
   ├─ "Passwords do not match"
   ├─ "Provide either email OR phone, not both"
   ├─ "Invalid email format"
   ├─ "Invalid phone format"
   ├─ "Email already registered"
   ├─ "Phone already registered"
   └─ "Invalid role choice"

C. RESPONSE FORMAT
   └─ {"message": "...", "user_id": "...", "auth_provider": "email|phone"}
```

**Validation Code Pattern:**
```python
class UserRegistrationSerializer(serializers.ModelSerializer):
    """
    Validates user registration input.
    Ensures password strength, email/phone uniqueness, and valid role.
    """
    password = serializers.CharField(
        write_only=True, required=True,
        validators=[validate_password],
        help_text="Password must be 8+ chars with uppercase/numbers"
    )
    password2 = serializers.CharField(write_only=True, required=True)
    email = serializers.EmailField(required=False, allow_blank=True)
    phone = PhoneNumberField(required=False, allow_blank=True)
    role = serializers.ChoiceField(
        choices=UnifiedUser.ROLE_CHOICES,
        help_text="Select role: vendor, client, staff, admin"
    )

    class Meta:
        model = UnifiedUser
        fields = ('email', 'phone', 'role', 'password', 'password2')

    def validate(self, attrs):
        """Comprehensive validation for registration."""
        try:
            # 1. Password match
            if attrs['password'] != attrs['password2']:
                raise serializers.ValidationError({
                    "password": _("Passwords do not match")
                })

            # 2. Email XOR Phone (not both, at least one)
            email = attrs.get('email')
            phone = attrs.get('phone')
            
            if email and phone:
                raise serializers.ValidationError({
                    "non_field_errors": _("Provide email OR phone, not both")
                })
            
            if not email and not phone:
                raise serializers.ValidationError({
                    "non_field_errors": _("Provide email OR phone, one required")
                })

            # 3. Uniqueness check
            if email and UnifiedUser.objects.filter(email=email).exists():
                raise serializers.ValidationError({
                    "email": _("Email already registered")
                })
            
            if phone and UnifiedUser.objects.filter(phone=phone).exists():
                raise serializers.ValidationError({
                    "phone": _("Phone already registered")
                })

            logger.info(f"✅ Registration validation passed for {email or phone}")
            return attrs
            
        except serializers.ValidationError:
            raise
        except Exception as e:
            logger.error(f"❌ Validation error: {str(e)}")
            raise serializers.ValidationError({
                "non_field_errors": _("Validation error occurred")
            })

    def create(self, validated_data):
        """Creates user via RegistrationService."""
        try:
            email = validated_data.get('email')
            phone = validated_data.get('phone')
            password = validated_data.pop('password')
            validated_data.pop('password2', None)
            
            user = RegistrationService.register_sync(
                email=email, phone=phone,
                password=password, **validated_data
            )
            return user
        except Exception as e:
            logger.error(f"❌ User creation failed: {str(e)}")
            raise serializers.ValidationError({
                "non_field_errors": str(e)
            })
```

---

#### **STEP 3: Implement Registration Views (Sync & Async)**

**Purpose:** HTTP endpoints for registration with throttling, error handling, and standardized responses.

**Location:** `apps/authentication/apis/auth/sync_views.py` and `async_views.py`

**Dependencies:**
- DRF GenericAPIView (sync)
- ADRF AsyncAPIView (async)
- Throttle classes
- Serializers

**Procedure:**

```
A. SYNC VIEW (DRF)
   └─ RegisterView(generics.CreateAPIView)
      1. Permission: AllowAny
      2. Throttle: BurstRateThrottle (10 req/min per IP)
      3. Post method
         ├─ Validate input with UserRegistrationSerializer
         ├─ Call RegistrationService.register_sync()
         ├─ Catch specific exceptions
         │  ├─ ValidationError (serializer)
         │  ├─ RegistrationException (service)
         │  └─ Exception (generic)
         └─ Return standardized JSON response
            ├─ 201 Created: {"success": true, "message": "...", "data": {...}}
            ├─ 400 Bad Request: {"success": false, "message": "...", "errors": {...}}
            └─ 500 Server Error: {"success": false, "message": "...", "error": "..."}

B. ASYNC VIEW (ADRF)
   └─ AsyncRegisterView(AsyncCreateAPIView)
      1. Same as sync, but async methods
      2. Await serializer validation
      3. Await RegistrationService.register_async()
      4. Return same response format

C. RESPONSE STANDARDS
   ├─ Success (201):
   │  {
   │    "success": true,
   │    "message": "Check email/phone for OTP",
   │    "data": {
   │      "user_id": "uuid",
   │      "auth_provider": "email|phone"
   │    }
   │  }
   ├─ Validation Error (400):
   │  {
   │    "success": false,
   │    "message": "Validation failed",
   │    "errors": {
   │      "password": ["Passwords do not match"],
   │      "email": ["Email already registered"]
   │    }
   │  }
   └─ Server Error (500):
      {
        "success": false,
        "message": "Registration failed",
        "error": "Internal server error"
      }
```

**View Code Pattern:**
```python
# apps/authentication/apis/auth/sync_views.py

class RegisterView(generics.CreateAPIView):
    """
    Synchronous user registration endpoint.
    
    HTTP: POST /api/v1/auth/register/
    Permission: AllowAny
    Throttle: BurstRateThrottle (10/min per IP)
    """
    queryset = UnifiedUser.objects.all()
    serializer_class = UserRegistrationSerializer
    permission_classes = [AllowAny]
    throttle_classes = [BurstRateThrottle]

    def create(self, request, *args, **kwargs):
        """
        Handles registration request with comprehensive error handling.
        
        Flow:
        1. Validate input (serializer)
        2. Create user (service)
        3. Generate + send OTP (service)
        4. Return response
        """
        try:
            # 1. Validate input
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            logger.info(f"✅ Serializer valid for {request.data.get('email_or_phone')}")

            # 2-4. Service handles user creation + OTP
            result = serializer.save()  # Calls RegistrationService.register_sync()
            
            logger.info(f"✅ Registration successful for user {result['user_id']}")
            return Response(
                {
                    "success": True,
                    "message": result['message'],
                    "data": result
                },
                status=status.HTTP_201_CREATED
            )

        except serializers.ValidationError as e:
            logger.warning(f"❌ Validation error: {e.detail}")
            return Response(
                {
                    "success": False,
                    "message": "Validation failed",
                    "errors": e.detail
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        except Exception as e:
            logger.error(f"❌ Registration error: {str(e)}", exc_info=True)
            return Response(
                {
                    "success": False,
                    "message": "Registration failed",
                    "error": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


# apps/authentication/apis/auth/async_views.py

class AsyncRegisterView(AsyncCreateAPIView):
    """
    Asynchronous user registration endpoint.
    
    HTTP: POST /api/v2/auth/register/
    Permission: AllowAny
    Throttle: BurstRateThrottle (10/min per IP, non-blocking)
    """
    queryset = UnifiedUser.objects.all()
    serializer_class = UserRegistrationSerializer
    permission_classes = [AllowAny]
    throttle_classes = [BurstRateThrottle]

    async def create(self, request, *args, **kwargs):
        """Asynchronous version of RegisterView.create()"""
        try:
            # 1. Validate input [ASYNC]
            serializer = self.get_serializer(data=request.data)
            await serializer.avalidate()  # If avalidate exists, else use sync
            logger.info(f"✅ Serializer valid [ASYNC]")

            # 2-4. Service handles user creation + OTP [ASYNC]
            result = await RegistrationService.register_async(
                email=request.data.get('email'),
                phone=request.data.get('phone'),
                password=request.data.get('password'),
                role=request.data.get('role', 'client'),
                request=request
            )
            
            logger.info(f"✅ Registration successful [ASYNC] for user {result['user_id']}")
            return Response(
                {
                    "success": True,
                    "message": result['message'],
                    "data": result
                },
                status=status.HTTP_201_CREATED
            )

        except Exception as e:
            logger.error(f"❌ Registration error [ASYNC]: {str(e)}", exc_info=True)
            return Response(
                {
                    "success": False,
                    "message": "Registration failed",
                    "error": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
```

---

### **SEGMENT 2: OTP VERIFICATION & RESEND (SYNC & ASYNC)**

#### **STEP 4: Implement OTP Verification Service (Both Sync & Async)**

**Purpose:** Verify user-provided OTP, activate account, and issue JWT tokens.

**Location:** `apps/authentication/services/otp_service.py` (extend existing)

**Dependencies:**
- OTPService (existing)
- CustomUserManager
- RefreshToken (JWT)
- Redis connection

**Procedure:**

```
A. SYNC VERIFICATION FLOW
   └─ OTPService.verify_otp_sync(user_id, otp, purpose='verify')
      1. Get Redis connection with retries
      2. Scan Redis for OTP key matching user_id + purpose
      3. Decrypt stored encrypted OTP
      4. Compare with provided OTP
         ├─ Match: Continue
         └─ No match: Return False + log warning
      5. On match:
         ├─ Delete OTP from Redis (one-time use)
         ├─ Mark user is_active=True, is_verified=True
         ├─ Generate JWT tokens (RefreshToken.for_user)
         ├─ Log successful verification
         └─ Return tokens + user info
      6. Exception handling: Log + return False

B. ASYNC VERIFICATION FLOW
   └─ OTPService.verify_otp_async(user_id, otp, purpose='verify')
      └─ Same as sync, but all I/O operations are awaited

C. TOKEN GENERATION
   ├─ refresh = RefreshToken.for_user(user)
   ├─ access = str(refresh.access_token)
   └─ Response includes: access, refresh, expires_in, user_info

D. INTEGRATION POINTS
   ├─ Redis: scan_iter + get + delete pattern
   ├─ User Model: is_active + is_verified fields
   ├─ JWT: SimpleJWT library
   └─ Logging: Every step with user_id, result, errors
```

**Code Pattern:**
```python
# In apps/authentication/services/otp_service.py

class OTPService:
    """..."""

    @staticmethod
    def verify_otp_sync(user_id: int, otp: str, purpose: str = 'verify') -> Dict[str, Any]:
        """
        Verifies OTP and activates user (synchronous).
        
        Steps:
        1. Scan Redis for OTP key
        2. Decrypt + compare OTP
        3. Activate user (is_active=True, is_verified=True)
        4. Generate JWT tokens
        5. Return tokens + user info
        """
        try:
            # 1. Get Redis connection
            redis_conn = get_redis_connection_safe()
            if not redis_conn:
                logger.error(f"❌ Redis unavailable for user {user_id}")
                raise Exception("Redis service temporarily unavailable")

            # 2. Scan for OTP key
            pattern = f"otp:{user_id}:{purpose}:*"
            keys = redis_conn.keys(pattern)
            
            if not keys:
                logger.warning(f"❌ No OTP found for user {user_id}")
                return None

            # 3. Try each key (should only be one)
            for redis_key in keys:
                encrypted_otp_stored = redis_conn.get(redis_key)
                if not encrypted_otp_stored:
                    continue
                
                # Decrypt + compare
                decrypted_otp = decrypt_otp(encrypted_otp_stored.decode())
                if decrypted_otp == otp:
                    # 4. Activate user
                    user = UnifiedUser.objects.get(id=user_id)
                    user.is_active = True
                    user.is_verified = True
                    user.save()
                    logger.info(f"✅ User {user_id} verified + activated")
                    
                    # 5. Delete OTP (one-time use)
                    redis_conn.delete(redis_key)
                    logger.info(f"✅ OTP deleted from Redis for user {user_id}")
                    
                    # 6. Generate tokens
                    refresh = RefreshToken.for_user(user)
                    tokens = {
                        'access': str(refresh.access_token),
                        'refresh': str(refresh),
                        'expires_in': 300,  # 5 minutes
                        'user': {
                            'id': str(user.id),
                            'email': user.email,
                            'phone': str(user.phone),
                            'role': user.role
                        }
                    }
                    
                    logger.info(f"✅ Tokens generated for user {user_id}")
                    return tokens

            # OTP not found after scanning
            logger.warning(f"❌ Invalid OTP for user {user_id}")
            return None

        except Exception as e:
            logger.error(f"❌ OTP verification failed: {str(e)}", exc_info=True)
            raise

    @staticmethod
    async def verify_otp_async(user_id: int, otp: str, purpose: str = 'verify') -> Dict[str, Any]:
        """Asynchronous version of verify_otp_sync()"""
        try:
            redis_conn = get_redis_connection_safe()
            if not redis_conn:
                logger.error(f"❌ Redis unavailable [ASYNC] for user {user_id}")
                raise Exception("Redis service temporarily unavailable")

            pattern = f"otp:{user_id}:{purpose}:*"
            keys = redis_conn.keys(pattern)
            
            if not keys:
                logger.warning(f"❌ No OTP found [ASYNC] for user {user_id}")
                return None

            for redis_key in keys:
                encrypted_otp_stored = redis_conn.get(redis_key)
                if not encrypted_otp_stored:
                    continue
                
                decrypted_otp = decrypt_otp(encrypted_otp_stored.decode())
                if decrypted_otp == otp:
                    # Activate user [ASYNC]
                    user = await UnifiedUser.objects.aget(id=user_id)
                    user.is_active = True
                    user.is_verified = True
                    await user.asave()
                    logger.info(f"✅ User {user_id} verified + activated [ASYNC]")
                    
                    redis_conn.delete(redis_key)
                    
                    # Generate tokens
                    refresh = RefreshToken.for_user(user)
                    tokens = {
                        'access': str(refresh.access_token),
                        'refresh': str(refresh),
                        'expires_in': 300,
                        'user': {
                            'id': str(user.id),
                            'email': user.email,
                            'phone': str(user.phone),
                            'role': user.role
                        }
                    }
                    
                    logger.info(f"✅ Tokens generated [ASYNC] for user {user_id}")
                    return tokens

            logger.warning(f"❌ Invalid OTP [ASYNC] for user {user_id}")
            return None

        except Exception as e:
            logger.error(f"❌ OTP verification failed [ASYNC]: {str(e)}", exc_info=True)
            raise
```

---

#### **STEP 5: Implement Resend OTP Service (Both Sync & Async)**

**Purpose:** Allow users to request a new OTP if the previous one expired.

**Location:** `apps/authentication/services/otp_service.py` (new method in OTPService)

**Dependencies:**
- OTPService methods
- EmailManager/SMSManager
- Redis connection

**Procedure:**

```
A. RESEND OTP FLOW (Sync & Async)
   1. Get user by email or phone
   2. Delete old OTP from Redis (scan + delete)
   3. Generate new OTP via OTPService.generate_otp_sync/async()
   4. Send via appropriate channel (email/SMS)
   5. Return success message

B. RATE LIMITING (handled by throttle class, not service)
   └─ Prevent spam: max X resend attempts per hour

C. RESPONSE
   └─ {"message": "New OTP sent to email/phone"}
```

**Code Pattern:**
```python
class OTPService:
    """..."""

    @staticmethod
    def resend_otp_sync(email_or_phone: str, purpose: str = 'verify') -> str:
        """
        Resends OTP via email or phone (sync version).
        
        Steps:
        1. Find user by email or phone
        2. Delete old OTP from Redis
        3. Generate new OTP
        4. Send email/SMS
        5. Return success message
        """
        try:
            # 1. Get user
            if '@' in email_or_phone:
                user = UnifiedUser.objects.get(email=email_or_phone, is_deleted=False)
            else:
                user = UnifiedUser.objects.get(phone=email_or_phone, is_deleted=False)
            
            logger.info(f"✅ User found for resend: {email_or_phone}")
            
            # 2. Delete old OTP from Redis
            redis_conn = get_redis_connection_safe()
            if not redis_conn:
                raise Exception("Redis unavailable")
            
            pattern = f"otp:{user.id}:{purpose}:*"
            keys = redis_conn.keys(pattern)
            for key in keys:
                redis_conn.delete(key)
            logger.info(f"✅ Old OTP deleted for user {user.id}")
            
            # 3. Generate new OTP
            otp = OTPService.generate_otp_sync(user.id, purpose=purpose)
            logger.info(f"✅ New OTP generated for user {user.id}")
            
            # 4. Send email/SMS
            if user.email:
                context = {'user_id': user.id, 'otp': otp}
                EmailManager.send_mail(
                    subject="Your New OTP",
                    recipients=[user.email],
                    template_name='otp.html',
                    context=context
                )
                logger.info(f"✅ OTP resent via email to {user.email}")
                return f"New OTP sent to {user.email}"
            else:
                body = f"Your new OTP: {otp}"
                SMSManager.send_sms(str(user.phone), body)
                logger.info(f"✅ OTP resent via SMS to {user.phone}")
                return f"New OTP sent to {user.phone}"

        except UnifiedUser.DoesNotExist:
            logger.warning(f"❌ User not found for resend: {email_or_phone}")
            # Return generic message (prevents user enumeration)
            return "If account exists, OTP has been resent"
        except Exception as e:
            logger.error(f"❌ Resend OTP failed: {str(e)}", exc_info=True)
            raise

    @staticmethod
    async def resend_otp_async(email_or_phone: str, purpose: str = 'verify') -> str:
        """Asynchronous version of resend_otp_sync()"""
        try:
            # 1. Get user [ASYNC]
            if '@' in email_or_phone:
                user = await UnifiedUser.objects.aget(
                    email=email_or_phone, is_deleted=False
                )
            else:
                user = await UnifiedUser.objects.aget(
                    phone=email_or_phone, is_deleted=False
                )
            
            logger.info(f"✅ User found [ASYNC] for resend: {email_or_phone}")
            
            # 2. Delete old OTP [ASYNC]
            redis_conn = get_redis_connection_safe()
            if not redis_conn:
                raise Exception("Redis unavailable")
            
            pattern = f"otp:{user.id}:{purpose}:*"
            keys = redis_conn.keys(pattern)
            for key in keys:
                redis_conn.delete(key)
            
            # 3. Generate new OTP [ASYNC]
            otp = await OTPService.generate_otp_async(user.id, purpose=purpose)
            
            # 4. Send email/SMS [ASYNC]
            if user.email:
                context = {'user_id': user.id, 'otp': otp}
                await EmailManager.asend_mail(
                    subject="Your New OTP",
                    recipients=[user.email],
                    template_name='otp.html',
                    context=context
                )
                logger.info(f"✅ OTP resent [ASYNC] via email to {user.email}")
                return f"New OTP sent to {user.email}"
            else:
                body = f"Your new OTP: {otp}"
                await SMSManager.asend_sms(str(user.phone), body)
                logger.info(f"✅ OTP resent [ASYNC] via SMS to {user.phone}")
                return f"New OTP sent to {user.phone}"

        except UnifiedUser.DoesNotExist:
            logger.warning(f"❌ User not found [ASYNC] for resend: {email_or_phone}")
            return "If account exists, OTP has been resent"
        except Exception as e:
            logger.error(f"❌ Resend OTP failed [ASYNC]: {str(e)}", exc_info=True)
            raise
```

---

#### **STEP 6: Implement OTP Verification & Resend Views (Sync & Async)**

**Purpose:** HTTP endpoints for OTP verification and resend requests.

**Location:** `apps/authentication/apis/auth/sync_views.py` and `async_views.py`

**View Classes:**
- `VerifyOTPView` (sync)
- `AsyncVerifyOTPView` (async)
- `ResendOTPView` (sync)
- `AsyncResendOTPView` (async)

**Procedure:**

```
A. VERIFY OTP VIEW
   ├─ HTTP: POST /api/v1/auth/verify-otp/
   ├─ Input: {"otp": "123456"}
   ├─ Steps:
   │  1. Validate OTP format (6 digits)
   │  2. Call OTPService.verify_otp_sync/async()
   │  3. If valid: Return tokens + user info (200)
   │  4. If invalid: Return error (400)
   │  5. If expired: Return error (400)
   └─ Response:
      ├─ Success: {"success": true, "data": {"access": "...", "refresh": "...", "user": {...}}}
      └─ Error: {"success": false, "message": "Invalid OTP"}

B. RESEND OTP VIEW
   ├─ HTTP: POST /api/v1/auth/resend-otp/
   ├─ Input: {"email_or_phone": "user@example.com or +1234567890"}
   ├─ Steps:
   │  1. Validate email_or_phone format
   │  2. Call OTPService.resend_otp_sync/async()
   │  3. Return success message (200)
   │  4. On error: Return generic message (prevents enumeration)
   └─ Response:
      ├─ Success: {"success": true, "message": "OTP resent"}
      └─ Error: {"success": true, "message": "If account exists, OTP resent"} [generic]
```

---

### **SEGMENT 3: LOGIN (SYNC & ASYNC)**

#### **STEP 7: Implement Login Service (Both Sync & Async)**

**Purpose:** Authenticate user with email/phone + password and issue JWT tokens.

**Location:** `apps/authentication/services/auth_service.py` (existing file, extend)

**Dependencies:**
- CustomUserManager
- RefreshToken (JWT)
- Logging
- Request object (for IP/user-agent)

**Procedure:**

```
A. LOGIN FLOW (Sync)
   1. Extract email_or_phone + password from request
   2. Query UnifiedUser by email OR phone
      ├─ User not found: Return 401
      ├─ User found: Continue
   3. Check password with user.check_password()
      ├─ Password mismatch: Return 401
      ├─ Password correct: Continue
   4. Check user.is_active (already verified)
      ├─ Not active: Return 403 (unverified)
      ├─ Active: Continue
   5. Check user.is_deleted
      ├─ Deleted: Return 401
      ├─ Not deleted: Continue
   6. Generate JWT tokens
      ├─ refresh = RefreshToken.for_user(user)
      ├─ access = str(refresh.access_token)
   7. Update last_login (user.save())
   8. Log successful login (with IP, user-agent)
   9. Return tokens + user info

B. LOGIN FLOW (Async)
   └─ Same as sync, but use:
      ├─ await UnifiedUser.objects.aget(...)
      ├─ await user.asave()
      └─ etc.

C. SECURITY NOTES
   ├─ Always use is_deleted check
   ├─ Log IP + user-agent for audit
   ├─ Don't reveal whether email/phone exists (generic error)
   ├─ Use constant-time password comparison (Django's check_password handles this)
   └─ Rate limiting handled by throttle class (not service)

D. RESPONSE FORMAT
   ├─ Success (200):
   │  {
   │    "success": true,
   │    "message": "Login successful",
   │    "data": {
   │      "access": "eyJ...",
   │      "refresh": "eyJ...",
   │      "user": {
   │        "id": "uuid",
   │        "email": "...",
   │        "phone": "...",
   │        "role": "client"
   │      }
   │    }
   │  }
   └─ Error (401):
      {
        "success": false,
        "message": "Invalid credentials"
      }
```

**Code Pattern:**
```python
class AuthService:
    """..."""

    @staticmethod
    def login_sync(email_or_phone: str, password: str, request=None) -> Dict[str, Any]:
        """
        Synchronous login flow with comprehensive validation and audit logging.
        """
        try:
            # 1. Query user by email or phone
            if '@' in email_or_phone:
                user = UnifiedUser.objects.get(
                    email=email_or_phone, is_deleted=False
                )
            else:
                user = UnifiedUser.objects.get(
                    phone=email_or_phone, is_deleted=False
                )
            
            logger.info(f"✅ User found: {email_or_phone}")

            # 2. Check password
            if not user.check_password(password):
                logger.warning(f"❌ Invalid password for {email_or_phone}")
                raise Exception("Invalid credentials")
            
            logger.info(f"✅ Password valid for {email_or_phone}")

            # 3. Check if user is active (verified)
            if not user.is_active:
                logger.warning(f"❌ User not active (unverified): {email_or_phone}")
                raise Exception("Account not verified. Check email/phone for OTP")

            # 4. Generate tokens
            refresh = RefreshToken.for_user(user)
            tokens = {
                'access': str(refresh.access_token),
                'refresh': str(refresh),
                'user': {
                    'id': str(user.id),
                    'email': user.email,
                    'phone': str(user.phone),
                    'role': user.role
                }
            }
            
            logger.info(f"✅ Tokens generated for {email_or_phone}")

            # 5. Update last_login
            user.last_login = timezone.now()
            user.save(update_fields=['last_login'])
            logger.info(f"✅ Last login updated for {email_or_phone}")

            # 6. Audit logging
            if request:
                ip_address = request.META.get('REMOTE_ADDR', 'unknown')
                user_agent = request.META.get('HTTP_USER_AGENT', 'unknown')
                logger.info(f"🔐 [LOGIN AUDIT] User: {email_or_phone}, IP: {ip_address}, User-Agent: {user_agent[:100]}")

            return tokens

        except UnifiedUser.DoesNotExist:
            logger.warning(f"❌ User not found: {email_or_phone}")
            raise Exception("Invalid credentials")
        except Exception as e:
            logger.error(f"❌ Login failed: {str(e)}", exc_info=True)
            raise

    @staticmethod
    async def login_async(email_or_phone: str, password: str, request=None) -> Dict[str, Any]:
        """Asynchronous version of login_sync()"""
        try:
            # 1. Query user [ASYNC]
            if '@' in email_or_phone:
                user = await UnifiedUser.objects.aget(
                    email=email_or_phone, is_deleted=False
                )
            else:
                user = await UnifiedUser.objects.aget(
                    phone=email_or_phone, is_deleted=False
                )
            
            logger.info(f"✅ User found [ASYNC]: {email_or_phone}")

            # 2. Check password (sync, but fast)
            if not user.check_password(password):
                logger.warning(f"❌ Invalid password [ASYNC] for {email_or_phone}")
                raise Exception("Invalid credentials")

            # 3. Check if active
            if not user.is_active:
                logger.warning(f"❌ User not active [ASYNC]: {email_or_phone}")
                raise Exception("Account not verified")

            # 4. Generate tokens
            refresh = RefreshToken.for_user(user)
            tokens = {
                'access': str(refresh.access_token),
                'refresh': str(refresh),
                'user': {
                    'id': str(user.id),
                    'email': user.email,
                    'phone': str(user.phone),
                    'role': user.role
                }
            }

            # 5. Update last_login [ASYNC]
            user.last_login = timezone.now()
            await user.asave(update_fields=['last_login'])

            # 6. Audit logging
            if request:
                ip_address = request.META.get('REMOTE_ADDR', 'unknown')
                user_agent = request.META.get('HTTP_USER_AGENT', 'unknown')
                logger.info(f"🔐 [LOGIN AUDIT ASYNC] User: {email_or_phone}, IP: {ip_address}")

            logger.info(f"✅ Login successful [ASYNC] for {email_or_phone}")
            return tokens

        except UnifiedUser.DoesNotExist:
            logger.warning(f"❌ User not found [ASYNC]: {email_or_phone}")
            raise Exception("Invalid credentials")
        except Exception as e:
            logger.error(f"❌ Login failed [ASYNC]: {str(e)}", exc_info=True)
            raise
```

---

#### **STEP 8: Implement Login Serializer & View (Sync & Async)**

**Purpose:** Validate login input and provide HTTP endpoints.

**Location:** `apps/authentication/serializers.py` and `apis/auth/sync_views.py` + `async_views.py`

**Serializer:**
```
LoginSerializer:
  ├─ Fields: email_or_phone, password
  ├─ Validation: Format check, not empty
  └─ Response: user object
```

**View:**
```
LoginView (Sync):
  ├─ HTTP: POST /api/v1/auth/login/
  ├─ Throttle: BurstRateThrottle
  └─ Call: AuthService.login_sync()

AsyncLoginView (Async):
  ├─ HTTP: POST /api/v2/auth/login/
  ├─ Throttle: BurstRateThrottle (non-blocking)
  └─ Call: await AuthService.login_async()
```

---

### **SEGMENT 4: GOOGLE AUTH & PASSWORD RESET**

#### **STEP 9: Implement Google OAuth Service & View (Async-Preferred)**

**Purpose:** Handle Google ID Token verification and user login/registration.

**Location:** `apps/authentication/services/google_service.py` (existing, extend)

**Dependencies:**
- `google-auth` library
- CustomUserManager
- RefreshToken (JWT)

**Procedure:**

```
A. GOOGLE AUTH FLOW
   1. Client sends Google ID Token
   2. Verify token with Google servers (verify_oauth2_token)
   3. Extract user info from token (email, name, picture)
   4. Check if user exists in database
      ├─ User exists: Update profile, generate tokens
      └─ User doesn't exist: Create user, generate tokens
   5. Mark auth_provider as 'google'
   6. Set is_verified=True (auto-verified by Google)
   7. Return tokens + user info

B. SYNC vs ASYNC
   ├─ Sync version: For backward compatibility
   └─ Async version: Preferred for production
      └─ Non-blocking I/O, handles concurrent requests

C. SECURITY NOTES
   ├─ Always verify token with Google (never trust client)
   ├─ Check token expiry
   ├─ Validate audience (client ID)
   └─ Don't create account if email already exists with different provider

D. RESPONSE
   └─ Same as login: {"access": "...", "refresh": "...", "user": {...}}
```

---

#### **STEP 10: Implement Password Reset & Change Service (Both Sync & Async)**

**Purpose:** Handle password reset (via email token or SMS OTP) and password change (authenticated users).

**Location:** `apps/authentication/services/password_service.py` (existing, extend)

**Procedure:**

```
A. PASSWORD RESET REQUEST FLOW
   1. User provides email or phone
   2. Find user
   3. Generate reset method:
      ├─ Email: Django token + urlsafe encoding
      │  ├─ Send email with reset link
      │  └─ User clicks link
      └─ Phone: 6-digit OTP
         ├─ Send SMS with OTP
         └─ User submits OTP
   4. Store in Redis with TTL (300 seconds)
   5. Return success message

B. PASSWORD RESET CONFIRM FLOW
   ├─ Email Method:
   │  1. Receive uidb64 + token + new_password
   │  2. Verify Django token
   │  3. Set new password
   │  4. Clear token from Redis
   │
   └─ Phone Method:
      1. Receive OTP + new_password
      2. Verify OTP against Redis
      3. Set new password
      4. Clear OTP from Redis

C. PASSWORD CHANGE FLOW (Authenticated Users)
   1. User provides old_password + new_password
   2. Verify old password matches
   3. Set new password
   4. Invalidate all existing tokens (security best practice)
   5. Return success + new tokens

D. INTEGRATION POINTS
   ├─ Email/SMS via EmailManager/SMSManager
   ├─ Redis for token/OTP storage
   ├─ Django token generator (for email flow)
   └─ JWT token generation
```

**Code Pattern:**
```python
class PasswordService:
    """Handles password reset and change operations"""

    @staticmethod
    def reset_password_request_sync(email_or_phone: str) -> str:
        """
        Initiates password reset (sync version).
        
        Steps:
        1. Find user
        2. Generate reset token/OTP
        3. Send email/SMS
        4. Return success message
        """
        try:
            # 1. Find user
            if '@' in email_or_phone:
                user = UnifiedUser.objects.get(email=email_or_phone)
            else:
                user = UnifiedUser.objects.get(phone=email_or_phone)
            
            # 2. Email flow: Generate Django token
            if user.email:
                token = default_token_generator.make_token(user)
                uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
                
                # Store in Redis
                redis_conn = get_redis_connection_safe()
                redis_key = f"reset:{user.id}:{uidb64}:{token}"
                redis_conn.setex(redis_key, 600, '1')  # 10 minutes
                
                # Send email
                reset_url = f"{FRONTEND_URL}/password-reset/{uidb64}/{token}/"
                EmailManager.send_mail(
                    subject="Password Reset",
                    recipients=[user.email],
                    template_name='password_reset.html',
                    context={'reset_url': reset_url}
                )
                logger.info(f"✅ Password reset email sent to {user.email}")
            
            # 3. Phone flow: Generate OTP
            else:
                otp = OTPService.generate_otp_sync(user.id, purpose='reset')
                body = f"Your password reset OTP: {otp}"
                SMSManager.send_sms(str(user.phone), body)
                logger.info(f"✅ Password reset OTP sent to {user.phone}")
            
            # 4. Return generic success (prevents user enumeration)
            return "If account exists, password reset instructions sent"

        except UnifiedUser.DoesNotExist:
            logger.warning(f"❌ User not found for password reset: {email_or_phone}")
            return "If account exists, password reset instructions sent"
        except Exception as e:
            logger.error(f"❌ Password reset request failed: {str(e)}", exc_info=True)
            raise

    @staticmethod
    def reset_password_confirm_sync(uidb64: str = None, token: str = None,
                                   otp: str = None, new_password: str = None) -> str:
        """
        Confirms password reset and sets new password (sync version).
        
        Supports two flows:
        1. Email: uidb64 + token + new_password
        2. Phone: otp + new_password
        """
        try:
            if uidb64 and token:
                # Email flow
                uid = force_str(urlsafe_base64_decode(uidb64))
                user = UnifiedUser.objects.get(pk=uid)
                
                if not default_token_generator.check_token(user, token):
                    raise Exception("Invalid or expired reset link")
                
                user.set_password(new_password)
                user.save()
                logger.info(f"✅ Password reset successful for {user.email}")
                
            elif otp:
                # Phone flow
                redis_conn = get_redis_connection_safe()
                pattern = f"otp:*:reset:*"
                keys = redis_conn.keys(pattern)
                
                user_id = None
                for redis_key in keys:
                    encrypted_otp_stored = redis_conn.get(redis_key)
                    if encrypted_otp_stored:
                        decrypted_otp = decrypt_otp(encrypted_otp_stored.decode())
                        if decrypted_otp == otp:
                            # Extract user_id from key
                            parts = redis_key.decode().split(':')
                            user_id = parts[1]
                            break
                
                if not user_id:
                    raise Exception("Invalid OTP")
                
                user = UnifiedUser.objects.get(id=user_id)
                user.set_password(new_password)
                user.save()
                logger.info(f"✅ Password reset successful for {user.phone}")
            
            return "Password reset successful"

        except Exception as e:
            logger.error(f"❌ Password reset confirm failed: {str(e)}")
            raise

    @staticmethod
    def change_password_sync(user_id: int, old_password: str, new_password: str) -> str:
        """
        Changes password for authenticated users (sync version).
        """
        try:
            user = UnifiedUser.objects.get(id=user_id)
            
            # Verify old password
            if not user.check_password(old_password):
                raise Exception("Current password is incorrect")
            
            # Set new password
            user.set_password(new_password)
            user.save()
            
            logger.info(f"✅ Password changed for user {user_id}")
            return "Password changed successfully"

        except Exception as e:
            logger.error(f"❌ Password change failed: {str(e)}")
            raise
```

---

## PART G: SUMMARY TABLE

| Step | Feature | Sync Path | Async Path | Service | Serializer | View |
|------|---------|-----------|-----------|---------|-----------|------|
| 1 | Registration | `register_sync()` | `register_async()` | RegistrationService | UserRegistrationSerializer | RegisterView / AsyncRegisterView |
| 2 | Registration Validation | ✅ | ✅ | Serializer | UserRegistrationSerializer | - |
| 3 | Registration Views | DRF | ADRF | - | - | RegisterView / AsyncRegisterView |
| 4 | OTP Verification | `verify_otp_sync()` | `verify_otp_async()` | OTPService | OTPSerializer | VerifyOTPView / AsyncVerifyOTPView |
| 5 | Resend OTP | `resend_otp_sync()` | `resend_otp_async()` | OTPService | ResendOTPSerializer | ResendOTPView / AsyncResendOTPView |
| 6 | OTP Views | DRF | ADRF | - | - | VerifyOTPView / ResendOTPView (async) |
| 7 | Login | `login_sync()` | `login_async()` | AuthService | LoginSerializer | LoginView / AsyncLoginView |
| 8 | Login Views | DRF | ADRF | - | - | LoginView / AsyncLoginView |
| 9 | Google Auth | `verify_and_login_sync()` | `verify_and_login_async()` | GoogleService | GoogleAuthSerializer | GoogleAuthView / AsyncGoogleAuthView |
| 10 | Password Reset | `reset_password_sync()` | `reset_password_async()` | PasswordService | PasswordResetSerializer | PasswordResetView / AsyncPasswordResetView |

---

## PART H: COMMON UTILITIES CHECKLIST

Every step MUST use these from `apps/common`:

- ✅ `apps/common/utils.py`:
  - `get_redis_connection_safe()` - Safe Redis with retries
  - `encrypt_otp()` - Fernet cipher
  - `decrypt_otp()` - Fernet decipher
  - `generate_numeric_otp()` - Secure random OTP
  - `get_otp_expiry_datetime()` - OTP expiry timestamp

- ✅ `apps/common/managers/email.py`:
  - `EmailManager.send_mail()` - Sync email
  - `EmailManager.asend_mail()` - Async email

- ✅ `apps/common/managers/sms.py`:
  - `SMSManager.send_sms()` - Sync SMS
  - `SMSManager.asend_sms()` - Async SMS

- ✅ `apps/authentication/managers.py`:
  - `CustomUserManager.create_user()` - Sync user creation
  - `CustomUserManager.acreate_user()` - Async user creation

- ✅ `apps/authentication/models.py`:
  - `UnifiedUser` model with merged Profile fields

---

## PART I: ERROR HANDLING & LOGGING STANDARDS

Every method MUST include:

```python
# 1. TRY-EXCEPT with specific error handling
try:
    # Business logic
except SpecificException as e:
    logger.warning(f"Expected error: {e}")
    raise
except Exception as e:
    logger.error(f"Unexpected error: {str(e)}", exc_info=True)
    raise

# 2. LOGGING LEVELS
logger.debug("Detailed trace info")      # Development only
logger.info("✅ Success checkpoint")      # Business events
logger.warning("⚠️ Unexpected but handled")# Recoverable errors
logger.error("❌ Critical error")         # Exceptions
logger.critical("🔥 System failure")      # System down

# 3. AUDIT LOGGING
logger.info(f"🔐 [AUDIT] Action: {action}, User: {user_id}, IP: {ip}, Timestamp: {timestamp}")
```

---

## CONCLUSION

This 10-step roadmap bridges your existing `userauths` implementation with the new industrial-grade `apps/authentication` + `apps/common` architecture.

**Key Architectural Patterns to Preserve:**
1. ✅ Atomic transactions for data consistency
2. ✅ Redis + encryption for OTP security
3. ✅ Dual-path (sync + async) for flexibility
4. ✅ Custom managers for optimized queries
5. ✅ Comprehensive logging + error handling
6. ✅ Celery → Django 6.0 native tasks (future)

**Next Action:** Wait for user confirmation before implementing any step.

---

## VERSION HISTORY
- **v1.0** (Jan 31, 2026): Initial study + 10-step roadmap (Study Phase Only)
