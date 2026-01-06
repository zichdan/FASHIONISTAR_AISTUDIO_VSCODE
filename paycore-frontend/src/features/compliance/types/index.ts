import { KYCLevel } from '@/types/common';

export type DocumentType =
  | 'national_id'
  | 'drivers_license'
  | 'passport'
  | 'utility_bill'
  | 'bank_statement'
  | 'selfie';

export type KYCStatus = 'pending' | 'under_review' | 'approved' | 'rejected';

export interface KYCVerification {
  id: string;
  user_id: string;
  level: KYCLevel;
  status: KYCStatus;
  documents: KYCDocument[];
  rejection_reason: string | null;
  submitted_at: string;
  reviewed_at: string | null;
  approved_at: string | null;
}

export interface KYCDocument {
  id: string;
  verification_id: string;
  document_type: DocumentType;
  file_url: string;
  file_name: string;
  status: KYCStatus;
  rejection_reason: string | null;
  uploaded_at: string;
}

export interface SubmitKYCRequest {
  level: KYCLevel;
  first_name: string;
  last_name: string;
  middle_name?: string;
  date_of_birth: string;
  nationality: string;
  address_line_1: string;
  address_line_2?: string;
  city: string;
  state: string;
  postal_code: string;
  country_id: string;
  document_type: DocumentType;
  document_number: string;
  document_expiry_date?: string;
  document_issuing_country_id: string;
  notes?: string;
  documents: {
    id_document: File;
    selfie: File;
    proof_of_address?: File;
  };
}

export interface KYCLevelInfo {
  level: KYCLevel;
  name: string;
  description: string;
  requirements: string[];
  benefits: string[];
  limits: {
    daily_transaction_limit: number;
    monthly_transaction_limit: number;
    wallet_balance_limit: number;
  };
  is_current: boolean;
  is_verified: boolean;
}

export interface CurrentKYCLevel {
  current_level: KYCLevel;
  level_info: KYCLevelInfo;
  next_level: KYCLevelInfo | null;
  verification_status: KYCStatus | null;
}
