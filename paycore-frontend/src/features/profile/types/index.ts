import { Country } from '@/types/common';

export interface Profile {
  id: string;
  user_id: string;
  phone_number: string | null;
  date_of_birth: string | null;
  bio: string | null;
  avatar: string | null;
  address_line_1: string | null;
  address_line_2: string | null;
  city: string | null;
  state: string | null;
  postal_code: string | null;
  country: Country | null;
  created_at: string;
  updated_at: string;
}

export interface UpdateProfileRequest {
  first_name?: string;
  last_name?: string;
  phone_number?: string;
  date_of_birth?: string;
  bio?: string;
  address_line_1?: string;
  address_line_2?: string;
  city?: string;
  state?: string;
  postal_code?: string;
  country_code?: string;
}

export interface UploadAvatarRequest {
  avatar: File;
}
