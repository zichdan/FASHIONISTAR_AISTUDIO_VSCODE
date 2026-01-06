export type TicketCategory =
  | 'account'
  | 'wallet'
  | 'transaction'
  | 'card'
  | 'loan'
  | 'investment'
  | 'bill_payment'
  | 'payment'
  | 'kyc'
  | 'security'
  | 'technical'
  | 'feedback'
  | 'other';

export type TicketPriority = 'low' | 'medium' | 'high' | 'urgent';
export type TicketStatus = 'open' | 'in_progress' | 'waiting_for_customer' | 'resolved' | 'closed';

export interface Ticket {
  id: string;
  user_id: string;
  subject: string;
  category: TicketCategory;
  priority: TicketPriority;
  status: TicketStatus;
  description: string;
  assigned_to: string | null;
  resolved_at: string | null;
  closed_at: string | null;
  rating: number | null;
  feedback: string | null;
  created_at: string;
  updated_at: string;
}

export interface CreateTicketRequest {
  subject: string;
  category: TicketCategory;
  priority?: TicketPriority;
  description: string;
}

export interface TicketMessage {
  id: string;
  ticket_id: string;
  sender_id: string;
  sender_name: string;
  sender_type: 'customer' | 'agent' | 'system';
  message: string;
  attachments: string[];
  created_at: string;
}

export interface AddMessageRequest {
  message: string;
  attachments?: File[];
}

export interface RateTicketRequest {
  rating: number;
  feedback?: string;
}

export interface TicketStatistics {
  total_tickets: number;
  open_tickets: number;
  resolved_tickets: number;
  average_resolution_time_hours: number;
  by_category: Record<TicketCategory, number>;
  by_status: Record<TicketStatus, number>;
}

export interface FAQ {
  id: string;
  question: string;
  answer: string;
  category: string;
  order: number;
  helpful_count: number;
  not_helpful_count: number;
}

export interface FAQCategory {
  name: string;
  slug: string;
  count: number;
}
