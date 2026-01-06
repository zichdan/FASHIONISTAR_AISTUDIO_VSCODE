export type NotificationType =
  | 'transaction'
  | 'security'
  | 'kyc'
  | 'loan'
  | 'investment'
  | 'card'
  | 'system'
  | 'marketing';

export type NotificationPriority = 'low' | 'medium' | 'high';

export interface Notification {
  id: string;
  user_id: string;
  type: NotificationType;
  title: string;
  message: string;
  priority: NotificationPriority;
  is_read: boolean;
  action_url: string | null;
  metadata: Record<string, unknown>;
  created_at: string;
  read_at: string | null;
}

export interface NotificationStatistics {
  total: number;
  unread: number;
  by_type: Record<NotificationType, number>;
  recent_count: number;
}

export interface MarkAsReadRequest {
  notification_ids?: string[];
  mark_all?: boolean;
}
