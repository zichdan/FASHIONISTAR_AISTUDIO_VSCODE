export type PaymentLinkStatus = 'active' | 'inactive' | 'expired';
export type InvoiceStatus = 'draft' | 'sent' | 'paid' | 'overdue' | 'cancelled';

export interface PaymentLink {
  id: string;
  user_id: string;
  wallet_id: string;
  title: string;
  description: string;
  amount: number;
  currency_code: string;
  slug: string;
  link_url: string;
  status: PaymentLinkStatus;
  max_uses: number | null;
  uses_count: number;
  expires_at: string | null;
  custom_fields: CustomField[];
  redirect_url: string | null;
  created_at: string;
  updated_at: string;
}

export interface CustomField {
  name: string;
  type: 'text' | 'email' | 'phone' | 'number';
  required: boolean;
  placeholder?: string;
}

export interface CreatePaymentLinkRequest {
  wallet_id: string;
  title: string;
  description?: string;
  amount: number;
  slug?: string;
  max_uses?: number;
  expires_at?: string;
  custom_fields?: CustomField[];
  redirect_url?: string;
}

export interface UpdatePaymentLinkRequest {
  title?: string;
  description?: string;
  amount?: number;
  status?: PaymentLinkStatus;
  max_uses?: number;
  expires_at?: string;
  redirect_url?: string;
}

export interface Invoice {
  id: string;
  user_id: string;
  wallet_id: string;
  invoice_number: string;
  customer_name: string;
  customer_email: string;
  customer_phone: string | null;
  customer_address: string | null;
  items: InvoiceItem[];
  subtotal: number;
  tax_percentage: number;
  tax_amount: number;
  discount_amount: number;
  total_amount: number;
  currency_code: string;
  status: InvoiceStatus;
  due_date: string;
  paid_at: string | null;
  notes: string | null;
  terms: string | null;
  created_at: string;
  updated_at: string;
}

export interface InvoiceItem {
  description: string;
  quantity: number;
  unit_price: number;
  amount: number;
}

export interface CreateInvoiceRequest {
  wallet_id: string;
  customer_name: string;
  customer_email: string;
  customer_phone?: string;
  customer_address?: string;
  items: InvoiceItem[];
  tax_percentage?: number;
  discount_amount?: number;
  due_date: string;
  notes?: string;
  terms?: string;
}

export interface UpdateInvoiceRequest {
  customer_name?: string;
  customer_email?: string;
  customer_phone?: string;
  customer_address?: string;
  items?: InvoiceItem[];
  tax_percentage?: number;
  discount_amount?: number;
  due_date?: string;
  status?: InvoiceStatus;
  notes?: string;
  terms?: string;
}

export interface Payment {
  id: string;
  user_id: string;
  wallet_id: string;
  payment_link_id: string | null;
  invoice_id: string | null;
  payer_name: string;
  payer_email: string;
  amount: number;
  fee: number;
  net_amount: number;
  currency_code: string;
  reference: string;
  status: 'pending' | 'completed' | 'failed';
  metadata: Record<string, unknown>;
  created_at: string;
}

export interface PayPaymentLinkRequest {
  payment_link_id: string;
  payer_name: string;
  payer_email: string;
  custom_field_values?: Record<string, string>;
}

export interface PayInvoiceRequest {
  invoice_id: string;
  payment_method: 'card' | 'bank_transfer';
}
