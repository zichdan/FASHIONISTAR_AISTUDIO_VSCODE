export type EventCategory =
  | 'authentication'
  | 'transactions'
  | 'account_management'
  | 'security'
  | 'compliance'
  | 'system';

export type SeverityLevel = 'info' | 'warning' | 'error' | 'critical';

export interface AuditLog {
  id: string;
  user_id: string | null;
  user_email: string | null;
  event: string;
  category: EventCategory;
  severity: SeverityLevel;
  description: string;
  ip_address: string;
  user_agent: string;
  device_info: Record<string, unknown>;
  metadata: Record<string, unknown>;
  created_at: string;
}

export interface AuditLogStatistics {
  total_logs: number;
  by_category: Record<EventCategory, number>;
  by_severity: Record<SeverityLevel, number>;
  recent_critical_count: number;
  recent_error_count: number;
}
