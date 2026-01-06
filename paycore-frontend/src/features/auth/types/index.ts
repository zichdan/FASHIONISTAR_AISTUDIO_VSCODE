export interface User {
  id: string;
  email: string;
  first_name: string;
  last_name: string;
  phone_number: string | null;
  phone: string | null;
  dob: string | null;
  bio: string | null;
  is_active: boolean;
  is_staff: boolean;
  kyc_level: string;
  push_enabled: boolean;
  in_app_enabled: boolean;
  email_enabled: boolean;
  biometrics_enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface RegisterRequest {
  first_name: string;
  last_name: string;
  email: string;
  password: string;
}

export interface LoginRequest {
  email: string;
  password: string;
}

export interface LoginResponse {
  message: string;
  otp_sent: boolean;
}

export interface VerifyOTPRequest {
  email: string;
  otp: number;
  device_token?: string;
  device_type?: 'web' | 'ios' | 'android';
}

export interface VerifyOTPResponse {
  access: string;
  refresh: string;
  user: User;
}

export interface RefreshTokenRequest {
  refresh: string;
}

export interface RefreshTokenResponse {
  access: string;
  refresh: string;
}

export interface ForgotPasswordRequest {
  email: string;
}

export interface ResetPasswordRequest {
  email: string;
  otp: number;
  new_password: string;
}

export interface ChangePasswordRequest {
  old_password: string;
  new_password: string;
}

export interface BiometricSetupRequest {
  device_id: string;
  device_name: string;
  biometric_type: 'fingerprint' | 'face_id' | 'other';
}

export interface BiometricSetupResponse {
  trust_token: string;
  device_id: string;
  expires_at: string;
}

export interface BiometricLoginRequest {
  email: string;
  trust_token: string;
  device_id: string;
}

export interface GoogleOAuthRequest {
  token: string;
  id_token?: string;
  device_token?: string;
  device_type?: 'web' | 'ios' | 'android';
}

export interface GoogleOAuthResponse {
  access: string;
  refresh: string;
  user?: User; // Optional since backend might not return user data
  is_new_user?: boolean;
}
