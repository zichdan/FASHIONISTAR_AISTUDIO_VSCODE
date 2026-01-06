/**
 * Firebase Cloud Messaging Service
 * Handles push notifications in the foreground
 */

import { initializeApp, getApps } from 'firebase/app';
import { getMessaging, getToken, onMessage, Messaging } from 'firebase/messaging';
import { firebaseConfig, vapidKey, isFirebaseConfigured } from '@/config/firebase.config';
import { registerServiceWorker } from '@/utils/registerServiceWorker';

let messaging: Messaging | null = null;
let serviceWorkerRegistration: ServiceWorkerRegistration | null = null;

/**
 * Initialize Firebase and get messaging instance
 */
export const initializeFirebaseMessaging = async (): Promise<Messaging | null> => {
  if (!isFirebaseConfigured()) {
    console.warn('[Firebase] Firebase not configured. Push notifications will not work.');
    return null;
  }

  try {
    // Register service worker first
    if (!serviceWorkerRegistration) {
      serviceWorkerRegistration = await registerServiceWorker();
      if (!serviceWorkerRegistration) {
        console.error('[Firebase] Failed to register service worker');
        return null;
      }
    }

    // Initialize Firebase app if not already initialized
    const app = getApps().length === 0 ? initializeApp(firebaseConfig) : getApps()[0];

    // Get messaging instance
    messaging = getMessaging(app);
    console.log('[Firebase] ✅ Firebase messaging initialized');

    return messaging;
  } catch (error) {
    console.error('[Firebase] Error initializing Firebase:', error);
    return null;
  }
};

/**
 * Request notification permission and get FCM token
 */
export const requestNotificationPermission = async (): Promise<string | null> => {
  try {
    // Check if notifications are supported
    if (!('Notification' in window)) {
      console.warn('[Firebase] This browser does not support notifications');
      return null;
    }

    // Request permission
    const permission = await Notification.requestPermission();

    if (permission !== 'granted') {
      console.log('[Firebase] Notification permission denied');
      return null;
    }

    // Initialize messaging if not already done
    if (!messaging) {
      messaging = await initializeFirebaseMessaging();
    }

    if (!messaging || !serviceWorkerRegistration) {
      return null;
    }

    // Get FCM token with service worker registration
    const token = await getToken(messaging, {
      vapidKey,
      serviceWorkerRegistration,
    });
    console.log('[Firebase] ✅ FCM token obtained:', token);

    return token;
  } catch (error) {
    console.error('[Firebase] Error getting FCM token:', error);
    return null;
  }
};

/**
 * Listen for foreground messages (when app is open)
 */
export const onForegroundMessage = async (callback: (payload: any) => void): Promise<(() => void) | null> => {
  if (!messaging) {
    messaging = await initializeFirebaseMessaging();
  }

  if (!messaging) {
    return null;
  }

  try {
    const unsubscribe = onMessage(messaging, (payload) => {
      console.log('[Firebase] 📩 Foreground message received:', payload);
      callback(payload);
    });

    return unsubscribe;
  } catch (error) {
    console.error('[Firebase] Error setting up foreground message listener:', error);
    return null;
  }
};

/**
 * Show browser notification
 */
export const showNotification = (title: string, options?: NotificationOptions) => {
  if (!('Notification' in window)) {
    console.warn('[Firebase] Notifications not supported');
    return;
  }

  if (Notification.permission === 'granted') {
    new Notification(title, {
      icon: '/favicon.ico',
      badge: '/favicon.ico',
      ...options,
    });
  }
};
