import { CardStatus, Currency } from '@/types/common';

export interface Card {
  card_id: string;
  user_id: string;
  wallet_id: string;
  card_type: 'virtual' | 'physical';
  card_brand: 'visa' | 'mastercard' | 'verve';
  card_number?: string; // Only available on create or detail view
  masked_number?: string; // Available in list view
  card_holder_name: string;
  expiry_month: number;
  expiry_year: number;
  cvv?: string; // Only available on create
  balance?: number;
  currency?: string;
  status: CardStatus;
  spending_limit: number | null;
  daily_limit: number | null;
  monthly_limit: number | null;
  is_frozen: boolean;
  allow_online_transactions: boolean;
  allow_atm_withdrawals: boolean;
  allow_international_transactions: boolean;
  total_spent?: number;
  created_at: string;
  updated_at?: string;
}

export interface BillingAddress {
  address_line_1: string;
  address_line_2?: string;
  city: string;
  state: string;
  postal_code: string;
  country: string;
}

export interface CardControls {
  online_payments: boolean;
  atm_withdrawals: boolean;
  international_transactions: boolean;
  contactless_payments: boolean;
}

export interface CreateCardRequest {
  wallet_id: string;
  card_type: 'virtual' | 'physical';
  card_brand: 'visa' | 'mastercard' | 'verve';
  nickname?: string;
  daily_limit?: number;
  monthly_limit?: number;
  billing_address?: BillingAddress;
}

export interface UpdateCardRequest {
  nickname?: string;
  daily_limit?: number;
  monthly_limit?: number;
  billing_address?: BillingAddress;
}

export interface FundCardRequest {
  amount: number;
  pin: string;
}

export interface UpdateCardControlsRequest {
  online_payments?: boolean;
  atm_withdrawals?: boolean;
  international_transactions?: boolean;
  contactless_payments?: boolean;
}

export interface CardTransaction {
  id: string;
  card_id: string;
  amount: number;
  currency: Currency;
  merchant_name: string;
  merchant_category: string;
  transaction_type: 'purchase' | 'withdrawal' | 'refund';
  status: 'pending' | 'completed' | 'declined' | 'reversed';
  description: string;
  created_at: string;
}
