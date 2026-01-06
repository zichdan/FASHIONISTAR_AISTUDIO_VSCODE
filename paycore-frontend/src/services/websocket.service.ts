/**
 * WebSocket Service for Real-time Notifications
 * Connects to Django Channels WebSocket endpoint
 */

export interface NotificationMessage {
  type: 'notification' | 'unread_count' | 'mark_read_response' | 'pong' | 'error';
  notification?: {
    notification_id: string;
    title: string;
    message: string;
    notification_type: string;
    priority: string;
    is_read: boolean;
    created_at: string;
    related_object_type?: string;
    related_object_id?: string;
    action_url?: string;
    action_data?: Record<string, any>;
    metadata?: Record<string, any>;
  };
  count?: number;
  timestamp?: string;
  message?: string;
  notification_ids?: string[];
}

type MessageCallback = (message: NotificationMessage) => void;
type ConnectionCallback = () => void;
type ErrorCallback = (error: Event) => void;

class WebSocketService {
  private socket: WebSocket | null = null;
  private url: string = '';
  private token: string = '';
  private reconnectAttempts: number = 0;
  private maxReconnectAttempts: number = 5;
  private reconnectDelay: number = 3000;
  private reconnectTimeout: NodeJS.Timeout | null = null;
  private heartbeatInterval: NodeJS.Timeout | null = null;
  private messageCallbacks: Set<MessageCallback> = new Set();
  private connectionCallbacks: Set<ConnectionCallback> = new Set();
  private disconnectCallbacks: Set<ConnectionCallback> = new Set();
  private errorCallbacks: Set<ErrorCallback> = new Set();
  private isIntentionalClose: boolean = false;

  /**
   * Connect to WebSocket
   * @param token - JWT access token for authentication
   */
  connect(token: string): void {
    // Prevent duplicate connections
    if (this.socket) {
      if (this.socket.readyState === WebSocket.OPEN) {
        return;
      } else if (this.socket.readyState === WebSocket.CONNECTING) {
        return;
      } else {
        // Close stale connection
        this.socket.close();
        this.socket = null;
      }
    }

    this.token = token;
    this.isIntentionalClose = false;

    // Determine WebSocket URL based on current API URL
    const apiUrl = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api/v1';
    const wsProtocol = apiUrl.startsWith('https') ? 'wss' : 'ws';
    const baseUrl = apiUrl.replace(/^https?:\/\//, '').replace('/api/v1', '');

    this.url = `${wsProtocol}://${baseUrl}/ws/notifications/?token=${token}`;

    this.socket = new WebSocket(this.url);
    this.socket.onopen = () => {
      this.reconnectAttempts = 0;
      this.startHeartbeat();
      this.connectionCallbacks.forEach(callback => callback());
    };

    this.socket.onmessage = (event) => {
      try {
        const message: NotificationMessage = JSON.parse(event.data);
        this.messageCallbacks.forEach(callback => callback(message));
      } catch (error) {
        console.error('[WebSocketService] Error parsing message:', error);
      }
    };

    this.socket.onerror = (error) => {
      this.errorCallbacks.forEach(callback => callback(error));
    };

    this.socket.onclose = () => {
      this.stopHeartbeat();
      this.disconnectCallbacks.forEach(callback => callback());

      // Attempt to reconnect if not intentional close
      if (!this.isIntentionalClose && this.reconnectAttempts < this.maxReconnectAttempts) {
        this.reconnectAttempts++;
        this.reconnectTimeout = setTimeout(() => {
          this.connect(this.token);
        }, this.reconnectDelay * this.reconnectAttempts);
      }
    };
  }

  /**
   * Disconnect from WebSocket
   */
  disconnect(): void {
    this.isIntentionalClose = true;

    if (this.reconnectTimeout) {
      clearTimeout(this.reconnectTimeout);
      this.reconnectTimeout = null;
    }

    this.stopHeartbeat();

    if (this.socket) {
      this.socket.close();
      this.socket = null;
    }

    this.reconnectAttempts = 0;
  }

  /**
   * Send a command to the WebSocket server
   */
  private send(data: any): void {
    if (this.socket && this.socket.readyState === WebSocket.OPEN) {
      this.socket.send(JSON.stringify(data));
    }
  }

  /**
   * Request current unread count
   */
  getUnreadCount(): void {
    this.send({ command: 'get_unread_count' });
  }

  /**
   * Mark notifications as read
   */
  markAsRead(notificationIds: string[]): void {
    this.send({ command: 'mark_read', notification_ids: notificationIds });
  }

  /**
   * Send heartbeat ping
   */
  private ping(): void {
    this.send({ command: 'ping' });
  }

  /**
   * Start heartbeat to keep connection alive
   */
  private startHeartbeat(): void {
    this.stopHeartbeat();
    // Send ping every 30 seconds
    this.heartbeatInterval = setInterval(() => {
      this.ping();
    }, 30000);
  }

  /**
   * Stop heartbeat
   */
  private stopHeartbeat(): void {
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
      this.heartbeatInterval = null;
    }
  }

  /**
   * Subscribe to messages
   */
  onMessage(callback: MessageCallback): () => void {
    this.messageCallbacks.add(callback);
    return () => this.messageCallbacks.delete(callback);
  }

  /**
   * Subscribe to connection events
   */
  onConnect(callback: ConnectionCallback): () => void {
    this.connectionCallbacks.add(callback);
    return () => this.connectionCallbacks.delete(callback);
  }

  /**
   * Subscribe to disconnect events
   */
  onDisconnect(callback: ConnectionCallback): () => void {
    this.disconnectCallbacks.add(callback);
    return () => this.disconnectCallbacks.delete(callback);
  }

  /**
   * Subscribe to error events
   */
  onError(callback: ErrorCallback): () => void {
    this.errorCallbacks.add(callback);
    return () => this.errorCallbacks.delete(callback);
  }

  /**
   * Check if WebSocket is connected
   */
  isConnected(): boolean {
    return this.socket !== null && this.socket.readyState === WebSocket.OPEN;
  }

  /**
   * Get current connection state
   */
  getReadyState(): number | null {
    return this.socket?.readyState ?? null;
  }
}

// Export singleton instance
export const websocketService = new WebSocketService();
