import { createApi, fetchBaseQuery } from '@reduxjs/toolkit/query/react';
import type { BaseQueryFn, FetchArgs, FetchBaseQueryError } from '@reduxjs/toolkit/query';
import type { ApiResponse } from '@/types/common';
import { setServerUnavailable } from '@/store/slices/serverStatusSlice';
import { logout } from '@/store/slices/authSlice';
import { isServerUnavailableError } from '@/utils/errorHandlers';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api/v1';

const baseQuery = fetchBaseQuery({
  baseUrl: API_BASE_URL,
  credentials: 'include', // Include cookies in requests for HTTP-only cookie support
  prepareHeaders: (headers) => {
    // Access token will be in HTTP-only cookie, but we check localStorage as fallback
    const token = localStorage.getItem('access_token');
    if (token) {
      headers.set('Authorization', `Bearer ${token}`);
    }
    headers.set('Content-Type', 'application/json');
    return headers;
  },
});

// Token refresh lock to prevent race conditions
let isRefreshing = false;
let refreshPromise: Promise<any> | null = null;

const baseQueryWithReauth: BaseQueryFn<string | FetchArgs, unknown, FetchBaseQueryError> = async (
  args,
  api,
  extraOptions
) => {
  let result = await baseQuery(args, api, extraOptions);

  // Check if server is unavailable (network errors, 502, 503, 504, etc.)
  if (result.error && isServerUnavailableError(result.error)) {
    api.dispatch(setServerUnavailable());
    return result;
  }

  if (result.error && result.error.status === 401) {
    // If already refreshing, wait for the existing refresh to complete
    if (isRefreshing && refreshPromise) {
      await refreshPromise;
      // Retry the original request with the new token
      result = await baseQuery(args, api, extraOptions);
      return result;
    }

    // Start refresh process
    isRefreshing = true;
    refreshPromise = baseQuery(
      {
        url: '/auth/refresh',
        method: 'POST',
        body: {}, // Empty body - backend will read refresh token from HTTP-only cookie
      },
      api,
      extraOptions
    );

    const refreshResult = await refreshPromise;

    if (refreshResult.data) {
      const data = refreshResult.data as ApiResponse<{ access: string }>;
      // Store the new access token in localStorage (refresh token stays in HTTP-only cookie)
      if (data.data.access) {
        localStorage.setItem('access_token', data.data.access);
      }

      // Reset refresh state
      isRefreshing = false;
      refreshPromise = null;

      // Retry the original query with new token
      result = await baseQuery(args, api, extraOptions);
    } else {
      // Reset refresh state
      isRefreshing = false;
      refreshPromise = null;

      // Refresh failed - dispatch logout action to clear Redux state and redirect to login
      api.dispatch(logout());
      window.location.href = '/login';
    }
  }

  return result;
};

export const baseApi = createApi({
  reducerPath: 'api',
  baseQuery: baseQueryWithReauth,
  tagTypes: [
    'Auth',
    'Profile',
    'Wallets',
    'Currencies',
    'Cards',
    'Transactions',
    'Bills',
    'Payments',
    'Loans',
    'Investments',
    'Support',
    'Compliance',
    'Notifications',
    'AuditLogs',
  ],
  endpoints: () => ({}),
});
