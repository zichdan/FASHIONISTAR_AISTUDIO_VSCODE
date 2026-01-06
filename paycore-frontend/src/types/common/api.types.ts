/**
 * Standard API Response Types
 */

export interface ApiResponse<T = unknown> {
  status: 'success' | 'failure';
  message: string;
  code: string | null;
  data: T;
}

export interface PaginatedResponse<T> {
  items: T[];
  page: number;
  limit: number;
  total: number;
  pages: number;
}

export interface ApiError {
  status: 'failure';
  message: string;
  code: string;
  data: null;
}

export interface PaginationParams {
  page?: number;
  limit?: number;
}

export interface FilterParams {
  search?: string;
  status?: string;
  start_date?: string;
  end_date?: string;
}

export type QueryParams = PaginationParams & FilterParams & Record<string, unknown>;
