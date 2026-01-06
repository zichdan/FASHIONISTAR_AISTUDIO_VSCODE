/**
 * Firebase Configuration
 *
 * To set up Firebase for your project:
 * 1. Go to Firebase Console: https://console.firebase.google.com/
 * 2. Create a new project or select existing one
 * 3. Go to Project Settings > General
 * 4. Scroll down to "Your apps" and click "Web app" icon
 * 5. Register your app and copy the config object
 * 6. Add the values to your .env file
 */

export const firebaseConfig = {
  apiKey: import.meta.env.VITE_FIREBASE_API_KEY || '',
  authDomain: import.meta.env.VITE_FIREBASE_AUTH_DOMAIN || '',
  projectId: import.meta.env.VITE_FIREBASE_PROJECT_ID || '',
  storageBucket: import.meta.env.VITE_FIREBASE_STORAGE_BUCKET || '',
  messagingSenderId: import.meta.env.VITE_FIREBASE_MESSAGING_SENDER_ID || '',
  appId: import.meta.env.VITE_FIREBASE_APP_ID || '',
  measurementId: import.meta.env.VITE_FIREBASE_MEASUREMENT_ID || '',
};

// VAPID Key for push notifications
// Get this from Firebase Console > Project Settings > Cloud Messaging > Web Push certificates
export const vapidKey = import.meta.env.VITE_FIREBASE_VAPID_KEY || '';

// Check if Firebase is configured
export const isFirebaseConfigured = (): boolean => {
  return !!(
    firebaseConfig.apiKey &&
    firebaseConfig.authDomain &&
    firebaseConfig.projectId &&
    firebaseConfig.messagingSenderId &&
    firebaseConfig.appId &&
    vapidKey
  );
};
