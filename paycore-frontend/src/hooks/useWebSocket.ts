import { useEffect, useState, useCallback, useRef } from 'react';
import { websocketService, type NotificationMessage } from '@/services/websocket.service';
import { useAppSelector } from './useAppSelector';

interface UseWebSocketReturn {
  isConnected: boolean;
  unreadCount: number;
  latestNotification: NotificationMessage['notification'] | null;
  connect: () => void;
  disconnect: () => void;
  markAsRead: (notificationIds: string[]) => void;
  refreshUnreadCount: () => void;
}

/**
 * Custom hook for WebSocket connection management
 * Automatically connects when user is authenticated
 */
export const useWebSocket = (): UseWebSocketReturn => {
  const [isConnected, setIsConnected] = useState(false);
  const [unreadCount, setUnreadCount] = useState(0);
  const [latestNotification, setLatestNotification] = useState<NotificationMessage['notification'] | null>(null);

  // Get authentication state from Redux store
  const { token, isAuthenticated } = useAppSelector((state) => state.auth);

  // Track if we've already set up listeners
  const listenersSetup = useRef(false);

  /**
   * Connect to WebSocket
   */
  const connect = useCallback(() => {
    if (token && isAuthenticated) {
      websocketService.connect(token);
    }
  }, [token, isAuthenticated]);

  /**
   * Disconnect from WebSocket
   */
  const disconnect = useCallback(() => {
    websocketService.disconnect();
  }, []);

  /**
   * Mark notifications as read
   */
  const markAsRead = useCallback((notificationIds: string[]) => {
    websocketService.markAsRead(notificationIds);
  }, []);

  /**
   * Refresh unread count
   */
  const refreshUnreadCount = useCallback(() => {
    websocketService.getUnreadCount();
  }, []);

  /**
   * Set up WebSocket event listeners
   */
  useEffect(() => {
    if (listenersSetup.current) return;

    // Handle incoming messages
    const unsubscribeMessage = websocketService.onMessage((message: NotificationMessage) => {
      switch (message.type) {
        case 'notification':
          // New notification received
          if (message.notification) {
            setLatestNotification(message.notification);
            // Optionally show a toast/alert here
            console.log('New notification:', message.notification);
          }
          break;

        case 'unread_count':
          // Unread count updated
          if (typeof message.count === 'number') {
            setUnreadCount(message.count);
          }
          break;

        case 'mark_read_response':
          // Notifications marked as read
          console.log('Marked as read:', message.notification_ids);
          // Refresh unread count
          websocketService.getUnreadCount();
          break;

        case 'pong':
          // Heartbeat response
          console.log('Pong received');
          break;

        case 'error':
          // Error message from server
          console.error('WebSocket error:', message.message);
          break;

        default:
          console.log('Unknown message type:', message);
      }
    });

    // Handle connection
    const unsubscribeConnect = websocketService.onConnect(() => {
      setIsConnected(true);
      console.log('WebSocket connected');
      // Request initial unread count
      websocketService.getUnreadCount();
    });

    // Handle disconnection
    const unsubscribeDisconnect = websocketService.onDisconnect(() => {
      setIsConnected(false);
      console.log('WebSocket disconnected');
    });

    // Handle errors
    const unsubscribeError = websocketService.onError((error) => {
      console.error('WebSocket error:', error);
    });

    listenersSetup.current = true;

    // Cleanup function
    return () => {
      unsubscribeMessage();
      unsubscribeConnect();
      unsubscribeDisconnect();
      unsubscribeError();
      listenersSetup.current = false;
    };
  }, []);

  /**
   * Auto-connect when authenticated
   */
  useEffect(() => {
    if (isAuthenticated && token && !websocketService.isConnected()) {
      connect();
    }

    // Cleanup: disconnect when component unmounts or user logs out
    return () => {
      if (!isAuthenticated) {
        disconnect();
      }
    };
  }, [isAuthenticated, token, connect, disconnect]);

  return {
    isConnected,
    unreadCount,
    latestNotification,
    connect,
    disconnect,
    markAsRead,
    refreshUnreadCount,
  };
};
