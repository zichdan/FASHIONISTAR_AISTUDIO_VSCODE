import { useEffect } from 'react';
import { useAppDispatch } from './index';
import { setServerUnavailable, setServerAvailable } from '@/store/slices/serverStatusSlice';

/**
 * Custom hook that performs a health check on the backend server when the app loads
 * If the server is unreachable, it displays the friendly error screen
 */
export const useHealthCheck = () => {
  const dispatch = useAppDispatch();

  useEffect(() => {
    const checkServerHealth = async () => {
      try {
        const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api/v1';

        // Try to reach the server's health endpoint (or any simple endpoint)
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 5000); // 5 second timeout

        const response = await fetch(`${API_BASE_URL}/healthcheck/`, {
          method: 'GET',
          signal: controller.signal,
        });

        clearTimeout(timeoutId);

        // If we get a response (even if it's an error), server is reachable
        if (response.ok || response.status === 404 || response.status === 401) {
          dispatch(setServerAvailable());
        } else if (response.status >= 500) {
          // Server error codes indicate server is down
          dispatch(setServerUnavailable());
        }
      } catch (error: any) {
        console.error('Health check failed:', error);

        // Network errors, timeouts, or connection refused = server unreachable
        if (
          error.name === 'AbortError' || // Timeout
          error.message?.includes('Failed to fetch') ||
          error.message?.includes('fetch failed') ||
          error.message === 'Network Error'
        ) {
          dispatch(setServerUnavailable());
        }
      }
    };

    checkServerHealth();
  }, [dispatch]);
};
