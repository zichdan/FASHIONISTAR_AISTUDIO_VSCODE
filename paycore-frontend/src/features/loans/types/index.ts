export type LoanType = 'personal' | 'business' | 'payday' | 'student';
export type LoanStatus = 'pending_approval' | 'approved' | 'active' | 'completed' | 'rejected' | 'defaulted';
export type RepaymentFrequency = 'daily' | 'weekly' | 'monthly';
export type InterestType = 'simple' | 'compound' | 'reducing_balance';

export interface LoanProduct {
  id: string;
  name: string;
  type: LoanType;
  description: string;
  min_amount: number;
  max_amount: number;
  min_tenure_months: number;
  max_tenure_months: number;
  interest_rate: number;
  interest_type: InterestType;
  processing_fee_percentage: number;
  late_payment_fee: number;
  currency_code: string;
  requirements: string[];
  is_active: boolean;
}

export interface LoanApplication {
  id: string;
  user_id: string;
  product: LoanProduct;
  wallet_id: string;
  amount: number;
  tenure_months: number;
  repayment_frequency: RepaymentFrequency;
  interest_amount: number;
  processing_fee: number;
  total_repayment: number;
  monthly_repayment: number;
  purpose: string;
  status: LoanStatus;
  rejection_reason: string | null;
  disbursement_date: string | null;
  maturity_date: string | null;
  created_at: string;
  updated_at: string;
}

export interface CreateLoanApplicationRequest {
  product_id: string;
  wallet_id: string;
  amount: number;
  tenure_months: number;
  repayment_frequency: RepaymentFrequency;
  purpose: string;
}

export interface CalculateLoanRequest {
  product_id: string;
  amount: number;
  tenure_months: number;
}

export interface CalculateLoanResponse {
  amount: number;
  interest_amount: number;
  processing_fee: number;
  total_repayment: number;
  monthly_repayment: number;
  interest_rate: number;
}

export interface LoanRepaymentSchedule {
  id: string;
  loan_id: string;
  installment_number: number;
  due_date: string;
  amount_due: number;
  principal_amount: number;
  interest_amount: number;
  amount_paid: number;
  status: 'pending' | 'paid' | 'overdue' | 'partial';
  paid_at: string | null;
}

export interface MakeRepaymentRequest {
  loan_id: string;
  amount: number;
  wallet_id: string;
  pin: string;
}

export interface LoanRepayment {
  id: string;
  loan_id: string;
  amount: number;
  payment_method: string;
  reference: string;
  status: 'completed' | 'failed';
  created_at: string;
}

export interface AutoRepaymentSettings {
  id: string;
  loan_id: string;
  wallet_id: string;
  is_enabled: boolean;
  is_suspended: boolean;
  suspended_until: string | null;
  created_at: string;
  updated_at: string;
}

export interface EnableAutoRepaymentRequest {
  loan_id: string;
  wallet_id: string;
}

export interface CreditScore {
  id: string;
  user_id: string;
  score: number;
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  factors: CreditScoreFactor[];
  last_updated: string;
}

export interface CreditScoreFactor {
  name: string;
  impact: 'positive' | 'negative' | 'neutral';
  description: string;
}

export interface LoanSummary {
  total_loans: number;
  active_loans: number;
  total_borrowed: number;
  total_repaid: number;
  outstanding_balance: number;
  next_repayment_date: string | null;
  next_repayment_amount: number | null;
}
