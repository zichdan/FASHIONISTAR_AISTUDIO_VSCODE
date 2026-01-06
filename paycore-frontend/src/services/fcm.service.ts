/**
 * Firebase Cloud Messaging Service
 * Handles push notification registration and token management
 */

import { initializeApp, type FirebaseApp } from 'firebase/app';
import { getMessaging, getToken, onMessage, type Messaging, isSupported } from 'firebase/messaging';
import { firebaseConfig, vapidKey, isFirebaseConfigured } from '@/config/firebase.config';

class FCMService {
  private app: FirebaseApp | null = null;
  private messaging: Messaging | null = null;
  private currentToken: string | null = null;
  private initialized: boolean = false;

  /**
   * Initialize Firebase and FCM
   */
  async initialize(): Promise<boolean> {
    if (this.initialized) {
      return true;
    }

    try {
      // Check if Firebase is properly configured
      if (!isFirebaseConfigured()) {
        console.warn('Firebase is not configured. Push notifications will not work.');
        console.warn('Please add Firebase configuration to your .env file.');
        return false;
      }

      // Check if FCM is supported in this browser
      const supported = await isSupported();
      if (!supported) {
        console.warn('Firebase Cloud Messaging is not supported in this browser');
        return false;
      }

      // Initialize Firebase
      this.app = initializeApp(firebaseConfig);
      this.messaging = getMessaging(this.app);
      this.initialized = true;

      console.log('Firebase Cloud Messaging initialized');
      return true;
    } catch (error) {
      console.error('Error initializing FCM:', error);
      return false;
    }
  }

  /**
   * Request notification permission from user
   */
  async requestPermission(): Promise<NotificationPermission> {
    if (!('Notification' in window)) {
      console.warn('This browser does not support notifications');
      return 'denied';
    }

    if (Notification.permission === 'granted') {
      return 'granted';
    }

    if (Notification.permission === 'denied') {
      return 'denied';
    }

    try {
      const permission = await Notification.requestPermission();
      return permission;
    } catch (error) {
      console.error('Error requesting notification permission:', error);
      return 'denied';
    }
  }

  /**
   * Get FCM token for push notifications
   * @returns Device token string or null if failed
   */
  async getDeviceToken(): Promise<string | null> {
    try {
      // Initialize if not already done
      if (!this.initialized) {
        const success = await this.initialize();
        if (!success || !this.messaging) {
          return null;
        }
      }

      // Check permission
      const permission = await this.requestPermission();
      if (permission !== 'granted') {
        console.warn('Notification permission not granted');
        return null;
      }

      // Get FCM token
      if (this.messaging) {
        const token = await getToken(this.messaging, { vapidKey });
        this.currentToken = token;
        console.log('FCM token obtained:', token);
        return token;
      }

      return null;
    } catch (error) {
      console.error('Error getting FCM token:', error);
      return null;
    }
  }

  /**
   * Set up foreground message listener
   * Handles notifications when app is in foreground
   */
  onForegroundMessage(callback: (payload: any) => void): (() => void) | null {
    if (!this.messaging) {
      console.warn('FCM not initialized');
      return null;
    }

    try {
      const unsubscribe = onMessage(this.messaging, (payload) => {
        console.log('Foreground message received:', payload);
        callback(payload);
      });

      return unsubscribe;
    } catch (error) {
      console.error('Error setting up foreground message listener:', error);
      return null;
    }
  }

  /**
   * Get current token if available
   */
  getCurrentToken(): string | null {
    return this.currentToken;
  }

  /**
   * Check if FCM is initialized
   */
  isInitialized(): boolean {
    return this.initialized;
  }

  /**
   * Get device type for registration
   */
  getDeviceType(): 'web' | 'ios' | 'android' {
    // Since this is a web app, always return 'web'
    // In a mobile app (React Native/Capacitor), you would detect the actual platform
    return 'web';
  }

  /**
   * Show browser notification (fallback when FCM not available)
   */
  async showNotification(title: string, options?: NotificationOptions): Promise<void> {
    if (!('Notification' in window)) {
      console.warn('Notifications not supported');
      return;
    }

    if (Notification.permission === 'granted') {
      try {
        new Notification(title, options);
      } catch (error) {
        console.error('Error showing notification:', error);
      }
    }
  }

  /**
   * Clear current token (useful for logout)
   */
  clearToken(): void {
    this.currentToken = null;
  }
}

// Export singleton instance
export const fcmService = new FCMService();
