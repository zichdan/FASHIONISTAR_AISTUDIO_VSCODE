# PayCore Authentication Pages

Comprehensive, production-ready authentication pages for the PayCore fintech platform.

## Pages Overview

### 1. LoginPage.tsx
**Route**: `/auth/login`

A modern login page with comprehensive authentication options.

**Features**:
- Email and password login with validation
- "Remember me" functionality
- Password visibility toggle
- Google OAuth integration (ready for implementation)
- Biometric login support (fingerprint/Face ID)
- Forgot password link
- Link to registration page
- Form validation using React Hook Form + Yup
- Error handling with toast notifications
- Loading states during authentication
- Navigate to OTP verification on successful login

**Form Fields**:
- Email (required, validated)
- Password (required, min 8 characters)
- Remember me (checkbox)

**Biometric Login**:
The page automatically detects if biometric authentication is available for the entered email. If a trust token exists in localStorage, it shows a "Sign in with Biometric" button.

**Usage**:
```tsx
import { LoginPage } from '@/pages/auth';
// or
import LoginPage from '@/pages/auth/LoginPage';
```

---

### 2. RegisterPage.tsx
**Route**: `/auth/register`

A comprehensive registration page with real-time password strength validation.

**Features**:
- First name, last name, email, and password fields
- Real-time password strength indicator
- Visual password requirements checklist
- Password confirmation validation
- Terms and conditions acceptance
- Password visibility toggle for both fields
- Form validation using React Hook Form + Yup
- Success message with auto-redirect to login
- Responsive design with proper spacing

**Form Fields**:
- First name (required, 2-50 characters)
- Last name (required, 2-50 characters)
- Email (required, valid email format)
- Password (required, must meet strength requirements)
- Confirm password (required, must match password)
- Terms acceptance (required checkbox)

**Password Requirements**:
- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- At least one special character

**Password Strength Indicator**:
- Weak (< 40%): Red
- Fair (40-59%): Orange
- Good (60-79%): Yellow
- Strong (80-100%): Green

**Usage**:
```tsx
import { RegisterPage } from '@/pages/auth';
// or
import RegisterPage from '@/pages/auth/RegisterPage';
```

---

### 3. VerifyOTPPage.tsx
**Route**: `/auth/verify-otp`

OTP verification page for two-factor authentication during login.

**Features**:
- 6-digit OTP input with individual boxes
- Auto-submit when all 6 digits are entered
- Resend OTP functionality with countdown timer (60 seconds)
- Visual feedback for OTP entry
- Security notice about OTP usage
- Error handling for invalid OTP
- Success handling with token storage and dashboard redirect
- Integration with Redux for state management

**Expected State**:
The page expects to receive the user's email via React Router's location state:
```tsx
navigate('/auth/verify-otp', { state: { email: 'user@example.com' } });
```

**Flow**:
1. User enters 6-digit OTP
2. OTP is automatically verified when complete
3. On success, tokens are saved to Redux store and localStorage
4. User is redirected to the dashboard
5. On error, OTP input is cleared and user can retry

**Resend OTP**:
- Initial countdown: 60 seconds
- Button becomes active after countdown
- Resets countdown when new OTP is sent

**Usage**:
```tsx
import { VerifyOTPPage } from '@/pages/auth';
// or
import VerifyOTPPage from '@/pages/auth/VerifyOTPPage';
```

---

### 4. ForgotPasswordPage.tsx
**Route**: `/auth/forgot-password`

Multi-step password reset flow with OTP verification.

**Features**:
- Two-step password reset process
- Progress indicator showing current step
- Email verification (Step 1)
- OTP verification and password reset (Step 2)
- Password strength indicator
- Visual password requirements checklist
- Ability to go back and change email
- Resend OTP with countdown timer
- Password visibility toggle
- Form validation at each step
- Success message with auto-redirect to login

**Step 1: Request OTP**
- Enter email address
- Server sends 6-digit OTP to email
- Progress to step 2

**Step 2: Reset Password**
- Display email (with option to change)
- Enter 6-digit OTP
- Enter new password with strength validation
- Confirm new password
- Submit to reset password

**Form Fields (Step 1)**:
- Email (required, valid email format)

**Form Fields (Step 2)**:
- OTP (6 digits)
- New password (required, must meet strength requirements)
- Confirm password (required, must match new password)

**Password Requirements** (same as registration):
- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- At least one special character

**Usage**:
```tsx
import { ForgotPasswordPage } from '@/pages/auth';
// or
import ForgotPasswordPage from '@/pages/auth/ForgotPasswordPage';
```

---

## Integration with Existing Code

### API Integration
All pages use the authentication API hooks from `@/features/auth/services/authApi`:
- `useLoginMutation` - Login
- `useRegisterMutation` - Registration
- `useVerifyOTPMutation` - OTP verification
- `useForgotPasswordMutation` - Request password reset OTP
- `useResetPasswordMutation` - Reset password with OTP
- `useBiometricLoginMutation` - Biometric authentication
- `useGoogleOAuthMutation` - Google OAuth (ready for implementation)

### Redux Integration
The pages integrate with Redux for state management:
- `setCredentials` - Store user data and tokens after successful authentication
- State updates are automatically persisted to localStorage

### Routing
Add these routes to your React Router configuration:

```tsx
import { LoginPage, RegisterPage, VerifyOTPPage, ForgotPasswordPage } from '@/pages/auth';

// In your router configuration:
<Route path="/auth/login" element={<LoginPage />} />
<Route path="/auth/register" element={<RegisterPage />} />
<Route path="/auth/verify-otp" element={<VerifyOTPPage />} />
<Route path="/auth/forgot-password" element={<ForgotPasswordPage />} />
```

---

## Design System

### Color Scheme
- Primary brand color: `brand.500` (#6366F1)
- Success: Green
- Error: Red
- Warning: Orange/Yellow
- Background: `gray.50`
- Cards: White with shadow

### Typography
- Headings: Bold, gradient text for main title
- Body: Inter font family
- Form labels: Semibold weight

### Spacing & Layout
- Maximum width: 28rem (md container)
- Consistent padding: 8-10
- Stack spacing: 6-8
- Card shadows: lg with border

### Components
- Chakra UI components throughout
- Custom gradients for branding
- Animated buttons with hover effects
- Responsive design for all screen sizes

---

## Form Validation

All forms use:
- **React Hook Form** - Form state management
- **Yup** - Schema validation
- **@hookform/resolvers** - Integration between RHF and Yup

### Validation Patterns
- Email: Standard email validation
- Password: Complex regex patterns for strength
- Required fields: Clear error messages
- Real-time validation feedback

---

## Error Handling

All API calls include comprehensive error handling:
- Toast notifications for success/error states
- Specific error messages from API responses
- Fallback error messages for network issues
- Loading states to prevent double submissions

### Toast Configuration
- Position: top-right
- Duration: 3000-5000ms
- Closable: true
- Status colors: success (green), error (red), warning (yellow), info (blue)

---

## Security Features

1. **Password Requirements**: Strong password policies enforced
2. **OTP Verification**: Two-factor authentication on login
3. **Token Storage**: Secure storage in localStorage and Redux
4. **Biometric Support**: Optional biometric authentication
5. **CSRF Protection**: Ready for CSRF token integration
6. **Security Notices**: User education about OTP security

---

## Accessibility

- Semantic HTML structure
- Proper form labels
- ARIA labels for icon buttons
- Keyboard navigation support
- Focus states for all interactive elements
- Error announcements via form validation

---

## Mobile Responsiveness

All pages are fully responsive:
- Single column layout on mobile
- Touch-friendly button sizes
- Optimized spacing for small screens
- Readable text sizes
- Proper input sizing for mobile keyboards

---

## Future Enhancements

1. **Google OAuth**: Complete implementation with Google SDK
2. **Biometric API**: Integrate with WebAuthn API for real biometric authentication
3. **Social Logins**: Add Facebook, Apple, GitHub logins
4. **Email Verification**: Add email verification step after registration
5. **Password Strength Meter**: Enhanced visual feedback
6. **Rate Limiting**: Client-side rate limiting for API calls
7. **Analytics**: Track authentication events
8. **A/B Testing**: Test different UI variations

---

## Troubleshooting

### Common Issues

**Issue**: OTP page redirects to login
**Solution**: Ensure email is passed via location state when navigating to `/auth/verify-otp`

**Issue**: Biometric login not showing
**Solution**: Biometric login only appears if trust token exists in localStorage for the entered email

**Issue**: Form validation not working
**Solution**: Ensure all required packages are installed: `react-hook-form`, `yup`, `@hookform/resolvers`

**Issue**: Toast notifications not appearing
**Solution**: Ensure ChakraProvider wraps your app in the root component

---

## Testing

### Manual Testing Checklist

**LoginPage**:
- [ ] Email validation works
- [ ] Password validation works
- [ ] Remember me persists email
- [ ] Forgot password link works
- [ ] Register link works
- [ ] Submit triggers login API
- [ ] Error handling displays toasts
- [ ] Loading state shows during API call

**RegisterPage**:
- [ ] All fields validate correctly
- [ ] Password strength indicator updates
- [ ] Password requirements checklist works
- [ ] Confirm password matches
- [ ] Terms checkbox required
- [ ] Success redirects to login
- [ ] Error handling displays toasts

**VerifyOTPPage**:
- [ ] OTP input accepts 6 digits
- [ ] Auto-submit on complete
- [ ] Resend countdown works
- [ ] Resend OTP button functions
- [ ] Success redirects to dashboard
- [ ] Error handling clears OTP
- [ ] Back to login works

**ForgotPasswordPage**:
- [ ] Step 1 sends OTP
- [ ] Step 2 shows after OTP sent
- [ ] Progress indicator updates
- [ ] Change email button works
- [ ] OTP validation works
- [ ] Password strength indicator works
- [ ] Success redirects to login
- [ ] Error handling at each step

---

## Dependencies

Required packages (already installed in project):
- `@chakra-ui/react` - UI components
- `@chakra-ui/icons` - Icons
- `react-hook-form` - Form management
- `yup` - Validation schemas
- `@hookform/resolvers` - RHF + Yup integration
- `react-router-dom` - Routing
- `react-icons` - Additional icons
- `@reduxjs/toolkit` - State management
- `react-redux` - Redux React bindings

---

## Support

For issues or questions:
1. Check the troubleshooting section above
2. Review the API documentation in `@/features/auth/services/authApi.ts`
3. Check Redux state configuration in `@/store/slices/authSlice.ts`
4. Review Chakra UI theme in `@/theme/index.ts`

---

## License

MIT License - Part of the PayCore Frontend Project
