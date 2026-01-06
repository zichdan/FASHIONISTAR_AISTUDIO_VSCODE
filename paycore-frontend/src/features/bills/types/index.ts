export type BillCategory =
  | 'airtime'
  | 'data'
  | 'electricity'
  | 'cable_tv'
  | 'internet'
  | 'water'
  | 'insurance'
  | 'education';

export interface BillProvider {
  id: string;
  name: string;
  category: BillCategory;
  logo: string;
  country: string;
  is_active: boolean;
  description: string;
}

export interface BillPackage {
  id: string;
  provider_id: string;
  name: string;
  code: string;
  amount: number;
  currency_code: string;
  validity_period: string | null;
  description: string;
  is_active: boolean;
}

export interface ValidateCustomerRequest {
  provider_id: string;
  customer_id: string;
}

export interface ValidateCustomerResponse {
  valid: boolean;
  customer_name: string;
  customer_info: Record<string, unknown>;
}

export interface PayBillRequest {
  wallet_id: string;
  provider_id: string;
  customer_id: string;
  package_id?: string;
  amount: number;
  phone_number?: string;
}

export interface BillPayment {
  id: string;
  user_id: string;
  wallet_id: string;
  provider: BillProvider;
  package: BillPackage | null;
  customer_id: string;
  amount: number;
  fee: number;
  total_amount: number;
  status: 'pending' | 'processing' | 'completed' | 'failed';
  token: string | null;
  pin: string | null;
  reference: string;
  provider_reference: string | null;
  provider_response: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}
