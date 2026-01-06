import { baseApi } from '@/store/api/baseApi';
import type { ApiResponse } from '@/types/common';
import type {
  RegisterRequest,
  LoginRequest,
  LoginResponse,
  VerifyOTPRequest,
  VerifyOTPResponse,
  RefreshTokenRequest,
  RefreshTokenResponse,
  ForgotPasswordRequest,
  ResetPasswordRequest,
  ChangePasswordRequest,
  BiometricSetupRequest,
  BiometricSetupResponse,
  BiometricLoginRequest,
  GoogleOAuthRequest,
  GoogleOAuthResponse,
  User,
} from '../types';

export const authApi = baseApi.injectEndpoints({
  endpoints: (builder) => ({
    // 1. Register
    register: builder.mutation<ApiResponse<User>, RegisterRequest>({
      query: (data) => ({
        url: '/auth/register',
        method: 'POST',
        body: data,
      }),
      invalidatesTags: ['Auth'],
    }),

    // 2. Login (Step 1 - Send OTP)
    login: builder.mutation<ApiResponse<LoginResponse>, LoginRequest>({
      query: (data) => ({
        url: '/auth/login',
        method: 'POST',
        body: data,
      }),
    }),

    // 3. Verify OTP (Step 2 - Complete login)
    verifyOTP: builder.mutation<ApiResponse<VerifyOTPResponse>, VerifyOTPRequest>({
      query: (data) => ({
        url: '/auth/login/verify',
        method: 'POST',
        body: data,
      }),
      invalidatesTags: ['Auth'],
    }),

    // 4. Refresh Token
    refreshToken: builder.mutation<ApiResponse<RefreshTokenResponse>, RefreshTokenRequest>({
      query: (data) => ({
        url: '/auth/refresh',
        method: 'POST',
        body: data,
      }),
    }),

    // 5. Logout
    logout: builder.mutation<ApiResponse<null>, void>({
      query: () => ({
        url: '/auth/logout',
        method: 'POST',
      }),
      invalidatesTags: ['Auth'],
    }),

    // 6. Forgot Password (Send OTP)
    forgotPassword: builder.mutation<ApiResponse<{ message: string }>, ForgotPasswordRequest>({
      query: (data) => ({
        url: '/auth/password/forgot',
        method: 'POST',
        body: data,
      }),
    }),

    // 7. Reset Password (with OTP)
    resetPassword: builder.mutation<ApiResponse<{ message: string }>, ResetPasswordRequest>({
      query: (data) => ({
        url: '/auth/password/reset',
        method: 'POST',
        body: data,
      }),
    }),

    // 8. Change Password (authenticated)
    changePassword: builder.mutation<ApiResponse<{ message: string }>, ChangePasswordRequest>({
      query: (data) => ({
        url: '/auth/password/change',
        method: 'POST',
        body: data,
      }),
    }),

    // 9. Setup Biometric Authentication
    setupBiometric: builder.mutation<ApiResponse<BiometricSetupResponse>, BiometricSetupRequest>({
      query: (data) => ({
        url: '/auth/biometric/setup',
        method: 'POST',
        body: data,
      }),
      invalidatesTags: ['Auth'],
    }),

    // 10. Biometric Login
    biometricLogin: builder.mutation<ApiResponse<VerifyOTPResponse>, BiometricLoginRequest>({
      query: (data) => ({
        url: '/auth/biometric/login',
        method: 'POST',
        body: data,
      }),
      invalidatesTags: ['Auth'],
    }),

    // 11. Disable Biometric
    disableBiometric: builder.mutation<ApiResponse<{ message: string }>, { device_id: string }>({
      query: (data) => ({
        url: '/auth/biometric/disable',
        method: 'POST',
        body: data,
      }),
      invalidatesTags: ['Auth'],
    }),

    // 12. Google OAuth Login
    googleOAuth: builder.mutation<ApiResponse<GoogleOAuthResponse>, GoogleOAuthRequest>({
      query: (data) => ({
        url: '/auth/google-login',
        method: 'POST',
        body: {
          token: data.id_token || data.token, // Backend expects 'token' field
          device_token: data.device_token,
          device_type: data.device_type,
        },
      }),
      invalidatesTags: ['Auth'],
    }),

    // 13. Verify Email
    verifyEmail: builder.mutation<ApiResponse<{ message: string }>, { token: string }>({
      query: (data) => ({
        url: '/auth/email/verify',
        method: 'POST',
        body: data,
      }),
      invalidatesTags: ['Auth'],
    }),

    // 14. Resend OTP
    resendOTP: builder.mutation<ApiResponse<{ message: string }>, { email: string }>({
      query: (data) => ({
        url: '/auth/resend-otp',
        method: 'POST',
        body: data,
      }),
    }),
  }),
});

export const {
  useRegisterMutation,
  useLoginMutation,
  useVerifyOTPMutation,
  useRefreshTokenMutation,
  useLogoutMutation,
  useForgotPasswordMutation,
  useResetPasswordMutation,
  useChangePasswordMutation,
  useSetupBiometricMutation,
  useBiometricLoginMutation,
  useDisableBiometricMutation,
  useGoogleOAuthMutation,
  useVerifyEmailMutation,
  useResendOTPMutation,
} = authApi;
