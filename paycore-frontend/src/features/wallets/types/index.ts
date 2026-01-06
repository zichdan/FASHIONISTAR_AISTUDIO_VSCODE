import { Currency, WalletStatus } from '@/types/common';

export interface Wallet {
  wallet_id: string;
  user_id: string;
  currency: Currency;
  name: string;
  wallet_type: 'main' | 'savings' | 'investment';
  balance: number;
  held_balance: number;
  available_balance: number;
  account_number: string;
  account_provider: string;
  status: WalletStatus;
  is_default: boolean;
  requires_pin: boolean;
  requires_biometric: boolean;
  created_at: string;
  updated_at: string;
}

export interface CreateWalletRequest {
  currency_code: string;
  name: string;
  wallet_type?: 'main' | 'savings' | 'investment';
  is_default?: boolean;
}

export interface UpdateWalletRequest {
  name?: string;
  is_default?: boolean;
}

export interface WalletBalance {
  balance: number;
  held_balance: number;
  available_balance: number;
  total_spent: number;
  currency: Currency;
}

export interface SetPinRequest {
  pin: number;
}

export interface ChangePinRequest {
  current_pin: number;
  new_pin: number;
}

export interface VerifyPinRequest {
  pin: string;
}

export interface HoldFundsRequest {
  amount: number;
  reason: string;
  expires_in_hours?: number;
}

export interface WalletHold {
  id: string;
  wallet_id: string;
  amount: number;
  reason: string;
  expires_at: string;
  released: boolean;
  created_at: string;
}

export interface WalletSummary {
  total_balance_usd: number;
  wallets: Wallet[];
  total_wallets: number;
}

export interface WalletSecurityStatus {
  pin_set: boolean;
  biometric_enabled: boolean;
  two_factor_enabled: boolean;
  last_pin_change: string | null;
}
