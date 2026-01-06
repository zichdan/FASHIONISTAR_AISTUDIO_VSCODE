import React, { createContext, useContext, useEffect, useState, useCallback, useRef } from 'react';
import { websocketService, type NotificationMessage } from '@/services/websocket.service';
import { useAppSelector } from '@/hooks';
import { useToast } from '@chakra-ui/react';

interface WebSocketContextValue {
  isConnected: boolean;
  unreadCount: number;
  latestNotification: NotificationMessage['notification'] | null;
  connect: () => void;
  disconnect: () => void;
  markAsRead: (notificationIds: string[]) => void;
  refreshUnreadCount: () => void;
}

const WebSocketContext = createContext<WebSocketContextValue | undefined>(undefined);

// Global Set to track shown notifications across all instances (prevents duplicates even with StrictMode)
const globalShownNotifications = new Set<string>();

interface WebSocketProviderProps {
  children: React.ReactNode;
}

export const WebSocketProvider: React.FC<WebSocketProviderProps> = ({ children }) => {
  const [isConnected, setIsConnected] = useState(false);
  const [unreadCount, setUnreadCount] = useState(0);
  const [latestNotification, setLatestNotification] = useState<NotificationMessage['notification'] | null>(null);

  // Get authentication state from Redux store
  const { accessToken: token, isAuthenticated } = useAppSelector((state) => state.auth);

  // Chakra UI toast
  const toast = useToast();

  // Track if we've already set up listeners
  const listenersSetup = useRef(false);

  /**
   * Connect to WebSocket
   */
  const connect = useCallback(() => {
    if (token && isAuthenticated) {
      console.log('[WebSocketProvider] Connecting to WebSocket...');
      websocketService.connect(token);
    }
  }, [token, isAuthenticated]);

  /**
   * Disconnect from WebSocket
   */
  const disconnect = useCallback(() => {
    console.log('[WebSocketProvider] Disconnecting from WebSocket...');
    websocketService.disconnect();
  }, []);

  /**
   * Mark notifications as read
   */
  const markAsRead = useCallback((notificationIds: string[]) => {
    console.log('[WebSocketProvider] Marking notifications as read:', notificationIds);
    websocketService.markAsRead(notificationIds);
  }, []);

  /**
   * Refresh unread count
   */
  const refreshUnreadCount = useCallback(() => {
    console.log('[WebSocketProvider] Refreshing unread count...');
    websocketService.getUnreadCount();
  }, []);

  /**
   * Set up WebSocket event listeners (only once)
   */
  useEffect(() => {
    if (listenersSetup.current) return;

    console.log('[WebSocketProvider] Setting up WebSocket listeners...');

    // Handle incoming messages
    const unsubscribeMessage = websocketService.onMessage((message: NotificationMessage) => {
      console.log('[WebSocketProvider] Received WebSocket message:', message);

      switch (message.type) {
        case 'notification':
          // New notification received
          if (message.notification) {
            const notif = message.notification;
            console.log('[WebSocketProvider] Received notification:', {
              id: notif.notification_id,
              title: notif.title,
              type: notif.notification_type,
              alreadyShown: notif.notification_id ? globalShownNotifications.has(notif.notification_id) : false,
            });

            // Check for duplicates using notification_id
            if (notif.notification_id && globalShownNotifications.has(notif.notification_id)) {
              console.log('[WebSocketProvider] ⚠️ DUPLICATE notification detected, skipping toast:', notif.notification_id);
              return;
            }

            // Mark as shown
            if (notif.notification_id) {
              globalShownNotifications.add(notif.notification_id);

              // Clean up old notification IDs (keep last 100)
              if (globalShownNotifications.size > 100) {
                const entries = Array.from(globalShownNotifications);
                entries.slice(0, globalShownNotifications.size - 100).forEach(id => {
                  globalShownNotifications.delete(id);
                });
              }
            }

            setLatestNotification(notif);

            // Show toast notification
            const isHighPriority = notif.priority === 'high' || notif.priority === 'urgent';

            // Determine toast color based on notification type
            let status: 'success' | 'info' | 'warning' | 'error' = 'success';
            if (notif.notification_type === 'transaction') {
              status = 'success';
            } else if (notif.notification_type === 'security') {
              status = 'warning';
            } else if (notif.notification_type === 'system') {
              status = 'info';
            } else {
              // Default for 'other' and unknown types
              status = 'success';
            }

            console.log('[WebSocketProvider] 🎉 Showing toast:', {
              title: notif.title,
              status,
              notification_id: notif.notification_id,
            });

            toast({
              title: notif.title,
              description: notif.message,
              status,
              duration: isHighPriority ? 7000 : 5000,
              isClosable: true,
              position: 'top-right',
            });
          }
          break;

        case 'unread_count':
          // Unread count updated
          if (typeof message.count === 'number') {
            console.log('[WebSocketProvider] Unread count updated:', message.count);
            setUnreadCount(message.count);
          }
          break;

        case 'mark_read_response':
          // Notifications marked as read
          console.log('[WebSocketProvider] Marked as read:', message.notification_ids);
          // Refresh unread count
          websocketService.getUnreadCount();
          break;

        case 'pong':
          // Heartbeat response
          console.log('[WebSocketProvider] Pong received');
          break;

        case 'error':
          // Error message from server
          console.error('[WebSocketProvider] WebSocket error:', message.message);
          break;

        default:
          console.log('[WebSocketProvider] Unknown message type:', message);
      }
    });

    // Handle connection
    const unsubscribeConnect = websocketService.onConnect(() => {
      console.log('[WebSocketProvider] WebSocket connected');
      setIsConnected(true);
      // Request initial unread count
      websocketService.getUnreadCount();
    });

    // Handle disconnection
    const unsubscribeDisconnect = websocketService.onDisconnect(() => {
      console.log('[WebSocketProvider] WebSocket disconnected');
      setIsConnected(false);
    });

    // Handle errors
    const unsubscribeError = websocketService.onError((error) => {
      console.error('[WebSocketProvider] WebSocket error:', error);
    });

    listenersSetup.current = true;

    // Cleanup function
    return () => {
      console.log('[WebSocketProvider] Cleaning up listeners...');
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
    console.log('[WebSocketProvider] Auth check:', {
      isAuthenticated,
      hasToken: !!token,
      tokenPreview: token ? token.substring(0, 20) + '...' : 'NO TOKEN',
      isConnected: websocketService.isConnected(),
    });

    if (isAuthenticated && token && !websocketService.isConnected()) {
      console.log('[WebSocketProvider] ✅ User authenticated, auto-connecting...');
      connect();
    } else if (!isAuthenticated) {
      console.log('[WebSocketProvider] ❌ User not authenticated, skipping connection');
    } else if (!token) {
      console.log('[WebSocketProvider] ❌ No token available, skipping connection');
    } else if (websocketService.isConnected()) {
      console.log('[WebSocketProvider] ✅ Already connected');
    }

    // Cleanup: disconnect when component unmounts or user logs out
    return () => {
      if (!isAuthenticated) {
        console.log('[WebSocketProvider] User logged out, disconnecting...');
        disconnect();
      }
    };
  }, [isAuthenticated, token, connect, disconnect]);

  const value: WebSocketContextValue = {
    isConnected,
    unreadCount,
    latestNotification,
    connect,
    disconnect,
    markAsRead,
    refreshUnreadCount,
  };

  return <WebSocketContext.Provider value={value}>{children}</WebSocketContext.Provider>;
};

/**
 * Hook to use WebSocket context
 */
export const useWebSocketContext = (): WebSocketContextValue => {
  const context = useContext(WebSocketContext);
  if (context === undefined) {
    throw new Error('useWebSocketContext must be used within a WebSocketProvider');
  }
  return context;
};
