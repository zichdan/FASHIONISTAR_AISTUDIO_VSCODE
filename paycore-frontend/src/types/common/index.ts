export * from './api.types';

export interface Currency {
  id: string;
  code: string;
  name: string;
  symbol: string;
  type: 'fiat' | 'crypto';
  is_active: boolean;
}

export interface Country {
  id: string;
  code: string;
  name: string;
  flag: string;
  phone_code: string;
  is_active: boolean;
}

export type TransactionStatus =
  | 'pending'
  | 'processing'
  | 'completed'
  | 'failed'
  | 'cancelled'
  | 'reversed';

export type KYCLevel = 'tier_0' | 'tier_1' | 'tier_2' | 'tier_3';

export type WalletStatus = 'active' | 'frozen' | 'suspended' | 'closed';

export type CardStatus = 'inactive' | 'active' | 'frozen' | 'blocked' | 'expired';
