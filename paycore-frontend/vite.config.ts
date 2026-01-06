import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';
import fs from 'fs';

// Plugin to inject environment variables into service worker
const injectEnvToServiceWorker = () => {
  return {
    name: 'inject-env-to-sw',
    generateBundle() {
      const swPath = path.resolve(__dirname, 'public/firebase-messaging-sw.js');
      if (fs.existsSync(swPath)) {
        let swContent = fs.readFileSync(swPath, 'utf-8');

        // Replace placeholders with actual env values
        swContent = swContent
          .replace('__VITE_FIREBASE_API_KEY__', process.env.VITE_FIREBASE_API_KEY || '')
          .replace('__VITE_FIREBASE_AUTH_DOMAIN__', process.env.VITE_FIREBASE_AUTH_DOMAIN || '')
          .replace('__VITE_FIREBASE_PROJECT_ID__', process.env.VITE_FIREBASE_PROJECT_ID || '')
          .replace('__VITE_FIREBASE_STORAGE_BUCKET__', process.env.VITE_FIREBASE_STORAGE_BUCKET || '')
          .replace('__VITE_FIREBASE_MESSAGING_SENDER_ID__', process.env.VITE_FIREBASE_MESSAGING_SENDER_ID || '')
          .replace('__VITE_FIREBASE_APP_ID__', process.env.VITE_FIREBASE_APP_ID || '')
          .replace('__VITE_FIREBASE_MEASUREMENT_ID__', process.env.VITE_FIREBASE_MEASUREMENT_ID || '');

        // Emit the processed service worker
        this.emitFile({
          type: 'asset',
          fileName: 'firebase-messaging-sw.js',
          source: swContent
        });
      }
    }
  };
};

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react(), injectEnvToServiceWorker()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
      '@/components': path.resolve(__dirname, './src/components'),
      '@/features': path.resolve(__dirname, './src/features'),
      '@/services': path.resolve(__dirname, './src/services'),
      '@/store': path.resolve(__dirname, './src/store'),
      '@/types': path.resolve(__dirname, './src/types'),
      '@/utils': path.resolve(__dirname, './src/utils'),
      '@/hooks': path.resolve(__dirname, './src/hooks'),
      '@/theme': path.resolve(__dirname, './src/theme'),
    },
  },
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: process.env.VITE_API_BASE_URL || 'http://localhost:8000',
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
    rollupOptions: {
      output: {
        manualChunks: {
          'react-vendor': ['react', 'react-dom', 'react-router-dom'],
          'chakra-vendor': ['@chakra-ui/react', '@emotion/react', '@emotion/styled'],
          'redux-vendor': ['@reduxjs/toolkit', 'react-redux'],
        },
      },
    },
  },
});
