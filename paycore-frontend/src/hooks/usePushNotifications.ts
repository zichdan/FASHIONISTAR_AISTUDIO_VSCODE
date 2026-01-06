import { useEffect } from 'react';
import { useToast } from '@chakra-ui/react';
import {
  initializeFirebaseMessaging,
  onForegroundMessage,
  showNotification,
} from '@/services/firebase.service';

/**
 * Hook to handle foreground push notifications
 * Shows browser notifications and Chakra toast when messages arrive while app is open
 */
export const usePushNotifications = () => {
  const toast = useToast();

  useEffect(() => {
    let unsubscribe: (() => void) | null = null;

    const setupPushNotifications = async () => {
      // Initialize Firebase messaging
      await initializeFirebaseMessaging();

      // Listen for foreground messages
      unsubscribe = await onForegroundMessage((payload) => {
        console.log('[usePushNotifications] Received foreground message:', payload);

        const { notification, data } = payload;

        // Show browser notification
        if (notification) {
          showNotification(notification.title || 'New Notification', {
            body: notification.body || '',
            icon: notification.icon || '/favicon.ico',
            data: data || {},
          });
        }

        // Show Chakra toast as well (more visible when app is focused)
        toast({
          title: notification?.title || 'New Notification',
          description: notification?.body || '',
          status: 'info',
          duration: 5000,
          isClosable: true,
          position: 'top-right',
        });
      });
    };

    setupPushNotifications();

    // Cleanup listener on unmount
    return () => {
      if (unsubscribe) {
        unsubscribe();
      }
    };
  }, [toast]);
};
