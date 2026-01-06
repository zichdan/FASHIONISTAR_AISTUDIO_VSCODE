import { TransactionStatus, Currency } from '@/types/common';

export type TransactionType =
  | 'transfer'
  | 'deposit'
  | 'withdrawal'
  | 'card_purchase'
  | 'card_funding'
  | 'bill_payment'
  | 'loan_disbursement'
  | 'loan_repayment'
  | 'investment'
  | 'investment_return';

export interface Transaction {
  id: string;
  user_id: string;
  wallet_id: string;
  type: TransactionType;
  amount: number;
  fee: number;
  total_amount: number;
  currency: Currency;
  status: TransactionStatus;
  reference: string;
  description: string;
  metadata: Record<string, unknown>;
  balance_before: number;
  balance_after: number;
  created_at: string;
  updated_at: string;
}

export interface TransferRequest {
  from_wallet_id: string;
  to_wallet_id: string;
  amount: number;
  description?: string;
  pin?: string;
  biometric_token?: string;
  device_id?: string;
}

export interface TransferResponse {
  transaction_id: string;
  reference: string;
  amount: number;
  fee: number;
  total: number;
  status: TransactionStatus;
  from_balance_after: number;
  to_balance_after: number;
}

export interface InitiateDepositRequest {
  wallet_id: string;
  amount: number;
  payment_method: 'card' | 'bank_transfer' | 'ussd' | 'qr';
  callback_url?: string;
}

export interface InitiateDepositResponse {
  transaction_id: string;
  payment_url: string;
  reference: string;
  status: TransactionStatus;
}

export interface VerifyDepositRequest {
  transaction_id: string;
}

export interface InitiateWithdrawalRequest {
  wallet_id: string;
  amount: number;
  bank_code: string;
  account_number: string;
  account_name: string;
  pin: string;
}

export interface WithdrawalResponse {
  transaction_id: string;
  reference: string;
  amount: number;
  fee: number;
  total: number;
  status: TransactionStatus;
  estimated_arrival: string;
}

export interface BankAccount {
  account_number: string;
  account_name: string;
  bank_code: string;
  bank_name: string;
}

export interface Bank {
  code: string;
  name: string;
  slug: string;
  country: string;
}

export interface TransactionStatistics {
  total_transactions: number;
  total_sent: string;
  total_received: string;
  total_fees: string;
  successful_count: number;
  failed_count: number;
  pending_count: number;
  average_transaction_amount: string;
}

export interface Dispute {
  id: string;
  transaction_id: string;
  user_id: string;
  type: 'unauthorized' | 'fraud' | 'not_received' | 'duplicate' | 'incorrect_amount';
  reason: string;
  evidence: string | null;
  status: 'pending' | 'investigating' | 'resolved' | 'rejected';
  resolution: string | null;
  created_at: string;
  updated_at: string;
}

export interface CreateDisputeRequest {
  dispute_type: 'unauthorized' | 'duplicate' | 'not_received' | 'defective' | 'refund_not_processed' | 'other';
  reason: string;
  disputed_amount?: number;
  evidence?: any;
}
