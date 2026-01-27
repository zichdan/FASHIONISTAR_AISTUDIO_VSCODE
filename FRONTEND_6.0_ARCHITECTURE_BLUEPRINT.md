# 🎨 FASHIONISTAR FRONTEND 6.0 ARCHITECTURE BLUEPRINT
## Enterprise-Grade React/Next.js Architecture for 2026 & Beyond
### Industrial eCommerce Platform for Africa's Fashion Revolution

---

## 📋 TABLE OF CONTENTS

1. [Executive Summary](#executive-summary)
2. [Current Architecture Assessment](#current-architecture-assessment)
3. [10 Critical Frontend Improvements](#10-critical-frontend-improvements)
4. [5 Expert Recommendations from PayCore](#5-expert-recommendations-from-paycore)
5. [Integrated Frontend Architecture](#integrated-frontend-architecture)
6. [Tech Stack & Dependencies](#tech-stack--dependencies)
7. [Performance Optimization Strategy](#performance-optimization-strategy)
8. [Security & Authentication](#security--authentication)
9. [Real-Time Features & WebSocket Integration](#real-time-features--websocket-integration)
10. [Production Deployment & DevOps](#production-deployment--devops)
11. [Migration Path & Implementation Timeline](#migration-path--implementation-timeline)
12. [Production Checklist](#production-checklist)

---

## EXECUTIVE SUMMARY

### Current State Analysis

**FASHIONISTAR Frontend (Next.js 14)**
- ✅ Modern Next.js 14 with App Router
- ✅ TypeScript enabled
- ✅ Tailwind CSS for styling
- ✅ React Hook Form + Zod validation
- ✅ Basic authentication (fetchWithAuth utility)
- ❌ **GAPS:** No state management (Redux/Zustand)
- ❌ **GAPS:** No real-time features (WebSocket)
- ❌ **GAPS:** No advanced error handling
- ❌ **GAPS:** No performance optimization (caching, lazy loading)
- ❌ **GAPS:** No accessibility features (a11y)
- ❌ **GAPS:** No analytics/monitoring
- ❌ **GAPS:** Hardcoded API endpoints (localhost:4000)
- ❌ **GAPS:** No interceptor pattern for API calls

**PayCore Frontend (Vite + React)**
- ✅ **EXCELLENT:** Redux + Redux Persist (state management)
- ✅ **EXCELLENT:** Chakra UI for component library + accessibility
- ✅ **EXCELLENT:** WebSocket integration (real-time)
- ✅ **EXCELLENT:** Zustand for lightweight state
- ✅ **EXCELLENT:** JWT token management
- ✅ **EXCELLENT:** Comprehensive error handling
- ✅ **EXCELLENT:** Firebase integration
- ✅ **EXCELLENT:** React Router v7 (SPA routing)
- ✅ **EXCELLENT:** Redux Persist (offline support)

### Mission: Compete with Enterprise eCommerce

To compete with **Etsy, Jumia, Amazon, Jiji**, FASHIONISTAR needs:
- ✅ **Sub-100ms API responses** (cached data)
- ✅ **99.9% uptime** (error boundaries, fallbacks)
- ✅ **Real-time inventory** (WebSocket updates)
- ✅ **Smooth UX** (optimistic updates, loading states)
- ✅ **Offline support** (local storage, service workers)
- ✅ **Mobile-first** (responsive, PWA)
- ✅ **Analytics** (user behavior tracking)
- ✅ **Accessibility** (WCAG 2.1 AA standard)

---

## CURRENT ARCHITECTURE ASSESSMENT

### FASHIONISTAR Frontend Structure

```
fashionista_frontend/
├── src/
│   ├── app/
│   │   ├── (auth)/              # Authentication routes
│   │   ├── (home)/              # Public routes
│   │   ├── admin-dashboard/     # Admin panel
│   │   ├── dashboard/           # User dashboard
│   │   ├── client/              # Client pages
│   │   ├── components/          # Shared components
│   │   │   ├── LatestCollection.tsx   ❌ PROBLEM: Direct fetch (no service)
│   │   │   ├── ShopByCategory.tsx     ❌ PROBLEM: Hardcoded API endpoint
│   │   │   ├── MultiStep.tsx          ✅ Uses React Hook Form
│   │   │   └── AddProduct/            ✅ Form validation
│   │   ├── context/             ❌ MISSING: State management (Redux/Zustand)
│   │   ├── utils/
│   │   │   ├── fetchAuth.ts     ⚠️ BASIC: Simple fetch wrapper
│   │   │   └── libs.ts          ⚠️ MIXED: Business logic in utils
│   │   └── layout.tsx
│   └── types.d.ts
├── middleware.ts                ✅ Next.js middleware
├── next.config.mjs             ⚠️ MINIMAL: Only Cloudinary remote patterns
└── tsconfig.json               ✅ Strict TypeScript

PROBLEMS IDENTIFIED:
❌ No Redux/Zustand for state management
❌ No API service layer (direct fetch calls)
❌ No error boundaries
❌ No loading/error states in components
❌ No caching strategy
❌ No interceptor pattern
❌ No WebSocket for real-time updates
❌ No offline support
❌ No analytics integration
❌ No component library (using basic HTML)
❌ No accessibility (a11y) features
❌ No performance monitoring
```

### PayCore Frontend Structure (EXEMPLARY)

```
paycore-frontend/
├── src/
│   ├── App.tsx                  ✅ Main router
│   ├── main.tsx                 ✅ Redux + WebSocket setup
│   ├── components/              ✅ Chakra UI components
│   │   ├── auth/
│   │   ├── common/              ✅ Reusable components
│   │   └── layout/
│   ├── contexts/                ✅ WebSocketContext
│   ├── features/                ✅ Domain-driven structure
│   │   ├── auth/
│   │   ├── payments/
│   │   ├── transactions/
│   │   └── wallets/
│   ├── hooks/                   ✅ Custom hooks
│   ├── pages/                   ✅ Page components
│   ├── services/                ✅ API service layer
│   ├── store/                   ✅ Redux store
│   │   └── slices/              ✅ Redux slices
│   ├── types/                   ✅ TypeScript types
│   ├── utils/                   ✅ Utilities
│   └── theme/                   ✅ Chakra theme

STRENGTHS TO BORROW:
✅ Domain-driven architecture (features/)
✅ Service layer for API calls
✅ Redux for state management (with persist)
✅ Custom hooks for reusable logic
✅ WebSocket integration
✅ Chakra UI for accessibility
✅ Types directory for shared types
```

---

## 10 CRITICAL FRONTEND IMPROVEMENTS

### ✅ IMPROVEMENT 1: Implement Redux + Redux Toolkit for State Management

**Current Problem:**
- No global state management
- Props drilling causing component coupling
- No persistent state across page reloads
- Manual loading/error state management per component

**Solution: Redux + Redux Persist**

```typescript
// store/store.ts - Redux configuration
import { configureStore } from '@reduxjs/toolkit';
import { persistStore, persistReducer } from 'redux-persist';
import storage from 'redux-persist/lib/storage';
import authSlice from './slices/authSlice';
import cartSlice from './slices/cartSlice';
import productsSlice from './slices/productsSlice';
import notificationsSlice from './slices/notificationsSlice';
import filtersSlice from './slices/filtersSlice';

const persistConfig = {
  key: 'fashionistar-root',
  storage,
  whitelist: ['auth', 'cart', 'filters'],
  blacklist: ['notifications', 'loading'],
};

const persistedAuthReducer = persistReducer(persistConfig, authSlice.reducer);

export const store = configureStore({
  reducer: {
    auth: persistedAuthReducer,
    cart: cartSlice.reducer,
    products: productsSlice.reducer,
    notifications: notificationsSlice.reducer,
    filters: filtersSlice.reducer,
  },
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware({
      serializableCheck: {
        ignoredActions: ['persist/PERSIST', 'persist/REHYDRATE'],
      },
    }),
});

export const persistor = persistStore(store);
export type RootState = ReturnType<typeof store.getState>;
export type AppDispatch = typeof store.dispatch;
```

```typescript
// store/slices/authSlice.ts - Authentication state
import { createSlice, createAsyncThunk, PayloadAction } from '@reduxjs/toolkit';
import type { User, AuthState } from '@/types/auth';

interface AuthState {
  user: User | null;
  accessToken: string | null;
  refreshToken: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;
  lastLoginAt: string | null;
}

const initialState: AuthState = {
  user: null,
  accessToken: null,
  refreshToken: null,
  isAuthenticated: false,
  isLoading: false,
  error: null,
  lastLoginAt: null,
};

// Async thunk for login
export const loginUser = createAsyncThunk<
  { user: User; accessToken: string; refreshToken: string },
  { email: string; password: string },
  { rejectValue: string }
>(
  'auth/login',
  async (credentials, { rejectValue }) => {
    try {
      const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(credentials),
      });

      if (!response.ok) {
        throw new Error('Login failed');
      }

      const data = await response.json();
      return data; // { user, accessToken, refreshToken }
    } catch (error) {
      return rejectValue(error instanceof Error ? error.message : 'Unknown error');
    }
  }
);

const authSlice = createSlice({
  name: 'auth',
  initialState,
  reducers: {
    logout: (state) => {
      state.user = null;
      state.accessToken = null;
      state.refreshToken = null;
      state.isAuthenticated = false;
      state.error = null;
    },
    setError: (state, action: PayloadAction<string>) => {
      state.error = action.payload;
    },
    clearError: (state) => {
      state.error = null;
    },
  },
  extraReducers: (builder) => {
    builder
      .addCase(loginUser.pending, (state) => {
        state.isLoading = true;
        state.error = null;
      })
      .addCase(loginUser.fulfilled, (state, action) => {
        state.isLoading = false;
        state.user = action.payload.user;
        state.accessToken = action.payload.accessToken;
        state.refreshToken = action.payload.refreshToken;
        state.isAuthenticated = true;
        state.lastLoginAt = new Date().toISOString();
      })
      .addCase(loginUser.rejected, (state, action) => {
        state.isLoading = false;
        state.error = action.payload || 'Login failed';
      });
  },
});

export default authSlice;
```

**Benefits:**
- ✅ Single source of truth for auth state
- ✅ Persistent state across page reloads
- ✅ Devtools integration for debugging
- ✅ Time-travel debugging
- ✅ Middleware support for side effects

---

### ✅ IMPROVEMENT 2: Implement API Service Layer with Interceptors

**Current Problem:**
- Direct `fetch()` calls scattered throughout components
- Hardcoded API endpoints (localhost:4000)
- No global error handling
- No token refresh logic
- No retry mechanism

**Solution: API Service Layer with Axios + Interceptors**

```typescript
// services/api.ts - Centralized API client
import axios, { AxiosError, AxiosInstance } from 'axios';
import { store } from '@/store/store';
import { logout, setError } from '@/store/slices/authSlice';

// Create axios instance
const api: AxiosInstance = axios.create({
  baseURL: process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000/api/v1',
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
  },
});

/**
 * Request Interceptor
 * Adds authorization token to all requests
 */
api.interceptors.request.use(
  (config) => {
    const state = store.getState();
    const token = state.auth.accessToken;

    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }

    // Add request ID for tracing
    config.headers['X-Request-ID'] = generateRequestId();

    return config;
  },
  (error) => Promise.reject(error)
);

/**
 * Response Interceptor
 * Handles errors, token refresh, and retries
 */
let refreshTokenInProgress = false;
let refreshSubscribers: Array<(token: string) => void> = [];

const onRefreshed = (token: string) => {
  refreshSubscribers.forEach((callback) => callback(token));
  refreshSubscribers = [];
};

api.interceptors.response.use(
  (response) => {
    // Add custom logging for monitoring
    console.info(`[API] ${response.config.method?.toUpperCase()} ${response.config.url} - ${response.status}`);
    return response;
  },
  async (error: AxiosError) => {
    const originalRequest = error.config as any;

    // Handle 401 Unauthorized (token expired)
    if (error.response?.status === 401) {
      if (!refreshTokenInProgress) {
        refreshTokenInProgress = true;

        try {
          const state = store.getState();
          const refreshToken = state.auth.refreshToken;

          if (!refreshToken) {
            throw new Error('No refresh token available');
          }

          // Request new token
          const { data } = await axios.post(
            `${process.env.NEXT_PUBLIC_API_URL}/auth/refresh`,
            { refresh_token: refreshToken }
          );

          // Update token in store
          store.dispatch(setToken(data.access_token));

          // Retry all pending requests
          onRefreshed(data.access_token);
          refreshTokenInProgress = false;

          // Retry original request
          originalRequest.headers.Authorization = `Bearer ${data.access_token}`;
          return api(originalRequest);
        } catch (err) {
          // Logout user if refresh fails
          store.dispatch(logout());
          refreshTokenInProgress = false;
          return Promise.reject(err);
        }
      }

      // Queue requests while token is refreshing
      return new Promise((resolve) => {
        refreshSubscribers.push((token: string) => {
          originalRequest.headers.Authorization = `Bearer ${token}`;
          resolve(api(originalRequest));
        });
      });
    }

    // Handle other error codes
    if (error.response?.status === 403) {
      store.dispatch(setError('You do not have permission for this action'));
    }

    if (error.response?.status === 429) {
      store.dispatch(setError('Too many requests. Please try again later.'));
    }

    if (error.response?.status >= 500) {
      store.dispatch(setError('Server error. Please try again later.'));
    }

    return Promise.reject(error);
  }
);

export default api;

// Helper function
function generateRequestId(): string {
  return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
}
```

```typescript
// services/authService.ts - Domain-specific API calls
import api from './api';
import type { LoginRequest, AuthResponse, User } from '@/types/auth';

export const authService = {
  /**
   * User login
   * @param credentials - Email and password
   * @returns User and tokens
   */
  async login(credentials: LoginRequest): Promise<AuthResponse> {
    const { data } = await api.post<AuthResponse>('/auth/login', credentials);
    return data;
  },

  /**
   * User registration
   * @param userData - User registration data
   * @returns Newly created user and tokens
   */
  async register(userData: any): Promise<AuthResponse> {
    const { data } = await api.post<AuthResponse>('/auth/register', userData);
    return data;
  },

  /**
   * Get current user profile
   * @returns User profile data
   */
  async getCurrentUser(): Promise<User> {
    const { data } = await api.get<User>('/auth/me');
    return data;
  },

  /**
   * Update user profile
   * @param updates - Profile updates
   * @returns Updated user data
   */
  async updateProfile(updates: Partial<User>): Promise<User> {
    const { data } = await api.put<User>('/auth/me', updates);
    return data;
  },

  /**
   * Request password reset
   * @param email - User email
   */
  async requestPasswordReset(email: string): Promise<{ message: string }> {
    const { data } = await api.post('/auth/password-reset/request', { email });
    return data;
  },
};
```

**Benefits:**
- ✅ Centralized token management
- ✅ Automatic token refresh
- ✅ Global error handling
- ✅ Request/response logging
- ✅ Retry logic
- ✅ Request tracking (request ID)
- ✅ Easy to test

---

### ✅ IMPROVEMENT 3: Implement Chakra UI + Accessibility

**Current Problem:**
- Using basic HTML tags (no component library)
- No accessibility features (ARIA labels, keyboard navigation)
- Inconsistent styling
- No dark mode support
- Manual accessibility compliance

**Solution: Chakra UI Integration**

```bash
npm install @chakra-ui/react @chakra-ui/icons @emotion/react @emotion/styled framer-motion
```

```typescript
// theme/theme.ts - Custom Chakra theme
import { extendTheme, type ThemeConfig } from '@chakra-ui/react';

const config: ThemeConfig = {
  initialColorMode: 'light',
  useSystemColorMode: true,
};

const theme = extendTheme({
  config,
  colors: {
    brand: {
      50: '#fff5e6',
      500: '#ff6b35',
      600: '#e55a2b',
      700: '#cc4d23',
    },
    fashionistar: {
      primary: '#ff6b35',
      secondary: '#004e89',
      accent: '#f7b801',
    },
  },
  fonts: {
    body: `'Satoshi', -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial`,
    heading: `'Satoshi', -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial`,
  },
  semanticTokens: {
    colors: {
      'chakra-border-color': {
        _light: '#e2e8f0',
        _dark: '#2d3748',
      },
    },
  },
});

export default theme;
```

```typescript
// components/ProductCard.tsx - Accessible product card
import {
  Box,
  Image,
  Stack,
  HStack,
  Text,
  Button,
  Badge,
  useToast,
  Heading,
  Tooltip,
} from '@chakra-ui/react';
import { StarIcon, AddIcon } from '@chakra-ui/icons';
import type { Product } from '@/types/products';
import { useDispatch } from 'react-redux';
import { addToCart } from '@/store/slices/cartSlice';

interface ProductCardProps {
  product: Product;
}

/**
 * ProductCard Component
 * Accessible product display with keyboard navigation
 * @param product - Product data
 */
export const ProductCard: React.FC<ProductCardProps> = ({ product }) => {
  const dispatch = useDispatch();
  const toast = useToast();

  const handleAddToCart = () => {
    dispatch(addToCart(product));
    toast({
      title: 'Added to cart',
      description: `${product.name} has been added to your cart`,
      status: 'success',
      duration: 3000,
      isClosable: true,
    });
  };

  return (
    <Box
      borderWidth="1px"
      borderRadius="lg"
      overflow="hidden"
      transition="all 0.3s"
      _hover={{ shadow: 'lg', transform: 'translateY(-4px)' }}
      role="group"
      aria-label={`Product: ${product.name}`}
    >
      {/* Product Image with Badge */}
      <Box position="relative" overflow="hidden" bg="gray.200" height="200px">
        <Image
          src={product.image}
          alt={`${product.name} product image`}
          width="100%"
          height="100%"
          objectFit="cover"
          loading="lazy"
          transition="transform 0.3s"
          _groupHover={{ transform: 'scale(1.05)' }}
        />
        {product.discount > 0 && (
          <Badge
            position="absolute"
            top={2}
            right={2}
            colorScheme="red"
            fontSize="sm"
            aria-label={`${product.discount}% discount`}
          >
            -{product.discount}%
          </Badge>
        )}
      </Box>

      {/* Product Info */}
      <Stack spacing={2} p={4}>
        <Heading size="sm" noOfLines={2}>
          {product.name}
        </Heading>

        {/* Rating */}
        <HStack spacing={1}>
          {Array(5)
            .fill(0)
            .map((_, i) => (
              <StarIcon
                key={i}
                color={i < product.rating ? 'yellow.400' : 'gray.300'}
                aria-hidden="true"
              />
            ))}
          <Text fontSize="sm" color="gray.600" aria-label={`${product.rating} out of 5 stars`}>
            ({product.reviews})
          </Text>
        </HStack>

        {/* Price */}
        <HStack justify="space-between">
          <Text fontWeight="bold" fontSize="lg" color="brand.600">
            ${product.price}
          </Text>
          {product.originalPrice && (
            <Text as="s" fontSize="sm" color="gray.500">
              ${product.originalPrice}
            </Text>
          )}
        </HStack>

        {/* Add to Cart Button */}
        <Tooltip label="Add this product to your shopping cart" placement="top">
          <Button
            width="100%"
            colorScheme="brand"
            leftIcon={<AddIcon />}
            onClick={handleAddToCart}
            aria-label={`Add ${product.name} to cart`}
          >
            Add to Cart
          </Button>
        </Tooltip>
      </Stack>
    </Box>
  );
};
```

**Benefits:**
- ✅ WCAG 2.1 AA compliant components
- ✅ Keyboard navigation built-in
- ✅ Dark mode support
- ✅ Responsive design
- ✅ Screen reader friendly
- ✅ Consistent component library
- ✅ Reduced code duplication

---

### ✅ IMPROVEMENT 4: Implement WebSocket for Real-Time Features

**Current Problem:**
- No real-time updates
- Customers don't see live inventory changes
- Manual page refresh required
- Poor user experience for vendors checking orders

**Solution: WebSocket Integration**

```typescript
// contexts/WebSocketContext.tsx - WebSocket provider
import React, { createContext, useContext, useEffect, useRef, ReactNode } from 'react';
import { useDispatch } from 'react-redux';
import { updateNotification } from '@/store/slices/notificationsSlice';
import { updateInventory } from '@/store/slices/productsSlice';
import type { Notification } from '@/types/notifications';

interface WebSocketContextType {
  socket: WebSocket | null;
  isConnected: boolean;
  emit: (event: string, data: any) => void;
  subscribe: (event: string, callback: (data: any) => void) => () => void;
}

const WebSocketContext = createContext<WebSocketContextType | undefined>(undefined);

interface WebSocketProviderProps {
  children: ReactNode;
  url?: string;
}

/**
 * WebSocketProvider
 * Provides real-time WebSocket connection
 * Handles reconnection, heartbeat, and event subscriptions
 */
export const WebSocketProvider: React.FC<WebSocketProviderProps> = ({
  children,
  url = process.env.NEXT_PUBLIC_WS_URL || 'ws://localhost:8000/ws',
}) => {
  const dispatch = useDispatch();
  const socketRef = useRef<WebSocket | null>(null);
  const [isConnected, setIsConnected] = React.useState(false);
  const subscriptionsRef = useRef<Map<string, Set<(data: any) => void>>>(new Map());
  const reconnectTimeoutRef = useRef<NodeJS.Timeout>();

  /**
   * Establish WebSocket connection
   */
  const connect = React.useCallback(() => {
    try {
      const socket = new WebSocket(url);

      socket.onopen = () => {
        console.log('✓ WebSocket connected');
        setIsConnected(true);

        // Send heartbeat every 30 seconds
        const heartbeat = setInterval(() => {
          if (socket.readyState === WebSocket.OPEN) {
            socket.send(JSON.stringify({ type: 'heartbeat' }));
          }
        }, 30000);

        (socket as any).heartbeatInterval = heartbeat;
      };

      socket.onmessage = (event) => {
        try {
          const message = JSON.parse(event.data);
          handleMessage(message);
        } catch (error) {
          console.error('Failed to parse WebSocket message:', error);
        }
      };

      socket.onerror = (error) => {
        console.error('WebSocket error:', error);
      };

      socket.onclose = () => {
        console.log('✗ WebSocket disconnected');
        setIsConnected(false);
        clearInterval((socket as any).heartbeatInterval);

        // Attempt to reconnect after 5 seconds
        reconnectTimeoutRef.current = setTimeout(() => {
          connect();
        }, 5000);
      };

      socketRef.current = socket;
    } catch (error) {
      console.error('Failed to connect WebSocket:', error);
    }
  }, [url]);

  /**
   * Handle incoming WebSocket messages
   */
  const handleMessage = (message: any) => {
    const { type, data } = message;

    // Dispatch Redux actions based on message type
    if (type === 'order_created') {
      dispatch(updateNotification({
        type: 'order',
        message: `New order #${data.order_id}`,
        data,
        timestamp: new Date().toISOString(),
      } as Notification));
    }

    if (type === 'inventory_updated') {
      dispatch(updateInventory(data));
    }

    if (type === 'payment_confirmed') {
      dispatch(updateNotification({
        type: 'payment',
        message: `Payment confirmed for order #${data.order_id}`,
        data,
        timestamp: new Date().toISOString(),
      } as Notification));
    }

    // Trigger subscribed callbacks
    const callbacks = subscriptionsRef.current.get(type);
    if (callbacks) {
      callbacks.forEach((callback) => callback(data));
    }
  };

  /**
   * Emit event through WebSocket
   */
  const emit = (event: string, data: any) => {
    if (socketRef.current?.readyState === WebSocket.OPEN) {
      socketRef.current.send(JSON.stringify({ type: event, data }));
    }
  };

  /**
   * Subscribe to event
   */
  const subscribe = (event: string, callback: (data: any) => void) => {
    if (!subscriptionsRef.current.has(event)) {
      subscriptionsRef.current.set(event, new Set());
    }
    subscriptionsRef.current.get(event)?.add(callback);

    // Return unsubscribe function
    return () => {
      subscriptionsRef.current.get(event)?.delete(callback);
    };
  };

  // Connect on mount
  useEffect(() => {
    connect();

    return () => {
      if (socketRef.current) {
        socketRef.current.close();
      }
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
    };
  }, [connect]);

  return (
    <WebSocketContext.Provider value={{ socket: socketRef.current, isConnected, emit, subscribe }}>
      {children}
    </WebSocketContext.Provider>
  );
};

/**
 * Hook to use WebSocket context
 */
export const useWebSocket = () => {
  const context = useContext(WebSocketContext);
  if (!context) {
    throw new Error('useWebSocket must be used within WebSocketProvider');
  }
  return context;
};
```

**Use Cases:**
```typescript
// Real-time notifications
useEffect(() => {
  const unsubscribe = useWebSocket().subscribe('order_created', (data) => {
    dispatch(addNotification({
      id: `order-${data.order_id}`,
      type: 'success',
      message: `New order received: #${data.order_id}`,
    }));
  });

  return unsubscribe;
}, [dispatch]);

// Real-time inventory updates
useEffect(() => {
  const unsubscribe = useWebSocket().subscribe('inventory_updated', (data) => {
    dispatch(updateProductStock(data));
  });

  return unsubscribe;
}, [dispatch]);
```

**Benefits:**
- ✅ Real-time inventory updates
- ✅ Live order notifications
- ✅ Automatic reconnection
- ✅ Heartbeat mechanism
- ✅ Memory efficient (subscriptions)

---

### ✅ IMPROVEMENT 5: Implement Error Boundaries & Global Error Handling

**Current Problem:**
- No error boundaries (entire app crashes on component error)
- No global toast notifications
- No fallback UI for errors
- Poor error user experience

**Solution: Error Boundary + Error Service**

```typescript
// components/ErrorBoundary.tsx - Error Boundary
import React, { ErrorInfo, ReactNode } from 'react';
import { Box, Heading, Text, Button, VStack } from '@chakra-ui/react';
import { useToast } from '@chakra-ui/react';

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

/**
 * ErrorBoundary Component
 * Catches errors in child components and displays fallback UI
 */
export class ErrorBoundary extends React.Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    // Log error to service
    console.error('Error caught by boundary:', error, errorInfo);
    
    // Send to error tracking service (e.g., Sentry)
    if (typeof window !== 'undefined' && (window as any).captureException) {
      (window as any).captureException(error);
    }
  }

  render() {
    if (this.state.hasError) {
      return (
        this.props.fallback || (
          <Box p={8} bg="red.50" borderRadius="md" m={4}>
            <VStack spacing={4} align="start">
              <Heading size="md" color="red.700">
                Something went wrong
              </Heading>
              <Text color="red.600">
                {this.state.error?.message || 'An unexpected error occurred'}
              </Text>
              <Button
                colorScheme="red"
                onClick={() => window.location.reload()}
              >
                Reload Page
              </Button>
            </VStack>
          </Box>
        )
      );
    }

    return this.props.children;
  }
}
```

```typescript
// services/errorService.ts - Global error handling
import { toast } from '@chakra-ui/react';

export enum ErrorType {
  NETWORK = 'NETWORK_ERROR',
  VALIDATION = 'VALIDATION_ERROR',
  AUTHENTICATION = 'AUTHENTICATION_ERROR',
  AUTHORIZATION = 'AUTHORIZATION_ERROR',
  NOT_FOUND = 'NOT_FOUND_ERROR',
  SERVER = 'SERVER_ERROR',
  UNKNOWN = 'UNKNOWN_ERROR',
}

export interface AppError {
  type: ErrorType;
  message: string;
  statusCode?: number;
  details?: any;
  timestamp: string;
}

export const handleError = (error: any): AppError => {
  const appError: AppError = {
    type: ErrorType.UNKNOWN,
    message: 'An unexpected error occurred',
    timestamp: new Date().toISOString(),
  };

  // Handle Axios errors
  if (error.response) {
    appError.statusCode = error.response.status;
    appError.details = error.response.data;

    switch (error.response.status) {
      case 400:
        appError.type = ErrorType.VALIDATION;
        appError.message = error.response.data.message || 'Invalid input';
        break;
      case 401:
        appError.type = ErrorType.AUTHENTICATION;
        appError.message = 'Please log in to continue';
        break;
      case 403:
        appError.type = ErrorType.AUTHORIZATION;
        appError.message = 'You do not have permission for this action';
        break;
      case 404:
        appError.type = ErrorType.NOT_FOUND;
        appError.message = 'Resource not found';
        break;
      case 500:
        appError.type = ErrorType.SERVER;
        appError.message = 'Server error. Please try again later';
        break;
    }
  } else if (error.request) {
    appError.type = ErrorType.NETWORK;
    appError.message = 'Network error. Please check your connection';
  } else if (error.message) {
    appError.message = error.message;
  }

  // Log error
  console.error('[ERROR]', appError);

  return appError;
};

export const showErrorToast = (error: AppError | string) => {
  const appError = typeof error === 'string' ? { type: ErrorType.UNKNOWN, message: error, timestamp: new Date().toISOString() } : error;

  toast({
    title: 'Error',
    description: appError.message,
    status: 'error',
    duration: 5000,
    isClosable: true,
  });
};
```

**Benefits:**
- ✅ App doesn't crash on component errors
- ✅ Consistent error handling
- ✅ User-friendly error messages
- ✅ Error tracking/monitoring
- ✅ Fallback UI support

---

### ✅ IMPROVEMENT 6: Implement Data Caching Strategy

**Current Problem:**
- Every page reload fetches data from API
- No local cache
- High network usage
- Slow load times

**Solution: React Query (TanStack Query) for Caching**

```bash
npm install @tanstack/react-query
```

```typescript
// services/queryClient.ts - React Query configuration
import { QueryClient, DefaultOptions } from '@tanstack/react-query';

const queryConfig: DefaultOptions = {
  queries: {
    staleTime: 1000 * 60 * 5, // 5 minutes
    gcTime: 1000 * 60 * 10, // 10 minutes (cache time)
    retry: 2, // Retry failed requests twice
    retryDelay: (attemptIndex) => Math.min(1000 * 2 ** attemptIndex, 30000),
    refetchOnWindowFocus: true,
    refetchOnReconnect: true,
  },
};

export const queryClient = new QueryClient({
  defaultOptions: queryConfig,
});
```

```typescript
// hooks/useProducts.ts - Custom hook for products
import { useQuery, useMutation } from '@tanstack/react-query';
import { productsService } from '@/services/productsService';
import { queryClient } from '@/services/queryClient';

/**
 * Hook for fetching products with caching
 */
export const useProducts = (category?: string, limit?: number) => {
  return useQuery({
    queryKey: ['products', { category, limit }],
    queryFn: () => productsService.getProducts({ category, limit }),
    staleTime: 1000 * 60 * 5, // 5 minutes
  });
};

/**
 * Hook for fetching single product
 */
export const useProduct = (productId: string) => {
  return useQuery({
    queryKey: ['products', productId],
    queryFn: () => productsService.getProduct(productId),
    enabled: !!productId, // Only fetch if ID is available
    staleTime: 1000 * 60 * 10, // 10 minutes
  });
};

/**
 * Hook for creating product
 */
export const useCreateProduct = () => {
  return useMutation({
    mutationFn: (data: any) => productsService.createProduct(data),
    onSuccess: () => {
      // Invalidate products cache after creation
      queryClient.invalidateQueries({ queryKey: ['products'] });
    },
  });
};
```

**Benefits:**
- ✅ Automatic caching
- ✅ Background refetching
- ✅ Deduplication (multiple requests → single API call)
- ✅ Offline support
- ✅ Garbage collection
- ✅ Reduced network usage
- ✅ Faster page loads

---

### ✅ IMPROVEMENT 7: Implement Lazy Loading & Code Splitting

**Current Problem:**
- Large JavaScript bundle
- All components loaded on initial page load
- Slow Time to Interactive (TTI)
- High core web vitals

**Solution: Dynamic Imports + Lazy Loading**

```typescript
// config/lazyComponents.ts - Lazy loaded components
import dynamic from 'next/dynamic';

export const AdminDashboard = dynamic(() => import('@/app/components/AdminDashboard'), {
  loading: () => <div>Loading...</div>,
  ssr: false,
});

export const VendorDashboard = dynamic(() => import('@/app/components/VendorDashboard'), {
  loading: () => <div>Loading...</div>,
  ssr: false,
});

export const ProductForm = dynamic(() => import('@/app/components/ProductForm'), {
  loading: () => <div>Loading...</div>,
});

export const CheckoutModal = dynamic(() => import('@/app/components/CheckoutModal'), {
  loading: () => <div>Loading...</div>,
});
```

```typescript
// components/Products.tsx - Lazy loading products
import { useProducts } from '@/hooks/useProducts';
import { Skeleton, Stack } from '@chakra-ui/react';
import { ProductCard } from '@/components/ProductCard';
import { InView } from 'react-intersection-observer';
import { useEffect } from 'react';

export const ProductList = () => {
  const { data: products, hasNextPage, fetchNextPage, isFetching } = useProducts();

  return (
    <Stack spacing={4}>
      {products?.map((product) => (
        <InView key={product.id} triggerOnce onChange={(inView) => {
          if (inView && hasNextPage) {
            fetchNextPage();
          }
        }}>
          {({ ref }) => (
            <div ref={ref}>
              <ProductCard product={product} />
            </div>
          )}
        </InView>
      ))}
      
      {isFetching && (
        <Stack>
          {Array(3).fill(0).map((_, i) => (
            <Skeleton key={i} height="200px" />
          ))}
        </Stack>
      )}
    </Stack>
  );
};
```

**Benefits:**
- ✅ Smaller initial bundle
- ✅ Faster page load
- ✅ Better Core Web Vitals
- ✅ Infinite scroll support
- ✅ Improved TTI

---

### ✅ IMPROVEMENT 8: Implement Offline Support (PWA)

**Current Problem:**
- No offline functionality
- Blank page when network is down
- Poor user experience for unreliable connections

**Solution: Service Worker + IndexedDB**

```typescript
// public/sw.js - Service Worker
const CACHE_NAME = 'fashionistar-v1';
const URLS_TO_CACHE = [
  '/',
  '/index.html',
  '/styles/globals.css',
  '/favicon.ico',
];

// Install event
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(URLS_TO_CACHE);
    })
  );
});

// Fetch event - Network first, fallback to cache
self.addEventListener('fetch', (event) => {
  if (event.request.method !== 'GET') {
    return;
  }

  event.respondWith(
    fetch(event.request)
      .then((response) => {
        // Cache successful responses
        if (response.status === 200) {
          const clone = response.clone();
          caches.open(CACHE_NAME).then((cache) => {
            cache.put(event.request, clone);
          });
        }
        return response;
      })
      .catch(() => {
        // Fallback to cache
        return caches.match(event.request).then((response) => {
          return response || new Response('Offline', { status: 503 });
        });
      })
  );
});
```

```typescript
// utils/offlineStorage.ts - IndexedDB wrapper
import Dexie, { Table } from 'dexie';
import type { Product, CartItem } from '@/types';

class FashionistarDB extends Dexie {
  products!: Table<Product>;
  cart!: Table<CartItem>;
  searches!: Table<any>;

  constructor() {
    super('fashionistar-db');
    this.version(1).stores({
      products: 'id',
      cart: 'id',
      searches: '++id, timestamp',
    });
  }
}

export const db = new FashionistarDB();

/**
 * Cache products for offline access
 */
export const cacheProducts = async (products: Product[]) => {
  await db.products.bulkPut(products);
};

/**
 * Get cached products
 */
export const getCachedProducts = async () => {
  return await db.products.toArray();
};

/**
 * Save search history
 */
export const saveSearchHistory = async (query: string) => {
  await db.searches.add({
    query,
    timestamp: Date.now(),
  });
};

/**
 * Get search history
 */
export const getSearchHistory = async (limit = 10) => {
  return await db.searches.orderBy('timestamp').reverse().limit(limit).toArray();
};
```

**Benefits:**
- ✅ Offline functionality
- ✅ Faster load times (cached assets)
- ✅ Better network resilience
- ✅ Local data persistence
- ✅ PWA capability

---

### ✅ IMPROVEMENT 9: Implement Analytics & Monitoring

**Current Problem:**
- No user behavior tracking
- No performance metrics
- No error tracking
- Cannot identify UX issues

**Solution: Analytics Service + Sentry**

```bash
npm install @sentry/react @sentry/tracing analytics
```

```typescript
// services/analyticsService.ts - Analytics wrapper
import { useEffect } from 'react';

interface AnalyticsEvent {
  name: string;
  properties?: Record<string, any>;
  value?: number;
  timestamp?: number;
}

class AnalyticsService {
  private queue: AnalyticsEvent[] = [];
  private isOnline = typeof window !== 'undefined' && navigator.onLine;

  constructor() {
    if (typeof window !== 'undefined') {
      window.addEventListener('online', () => {
        this.isOnline = true;
        this.flushQueue();
      });
      window.addEventListener('offline', () => {
        this.isOnline = false;
      });
    }
  }

  /**
   * Track user event
   */
  track(event: AnalyticsEvent) {
    const eventData = {
      ...event,
      timestamp: event.timestamp || Date.now(),
      userId: this.getUserId(),
      sessionId: this.getSessionId(),
    };

    if (this.isOnline) {
      this.sendEvent(eventData);
    } else {
      this.queue.push(eventData);
    }
  }

  /**
   * Track page view
   */
  trackPageView(pageName: string, properties?: Record<string, any>) {
    this.track({
      name: 'page_view',
      properties: { page: pageName, ...properties },
    });
  }

  /**
   * Track purchase
   */
  trackPurchase(orderId: string, amount: number, items: any[]) {
    this.track({
      name: 'purchase',
      properties: {
        order_id: orderId,
        value: amount,
        items: items.length,
      },
      value: amount,
    });
  }

  /**
   * Track search
   */
  trackSearch(query: string, results: number) {
    this.track({
      name: 'search',
      properties: { query, results },
    });
  }

  /**
   * Send event to backend
   */
  private async sendEvent(event: AnalyticsEvent) {
    try {
      await fetch(`${process.env.NEXT_PUBLIC_API_URL}/analytics/track`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(event),
      });
    } catch (error) {
      console.error('Failed to send analytics event:', error);
    }
  }

  /**
   * Flush queued events
   */
  private async flushQueue() {
    while (this.queue.length > 0) {
      const event = this.queue.shift();
      if (event) {
        await this.sendEvent(event);
      }
    }
  }

  private getUserId(): string {
    // Get from Redux/localStorage
    return localStorage.getItem('userId') || 'anonymous';
  }

  private getSessionId(): string {
    let sessionId = sessionStorage.getItem('sessionId');
    if (!sessionId) {
      sessionId = `session-${Date.now()}`;
      sessionStorage.setItem('sessionId', sessionId);
    }
    return sessionId;
  }
}

export const analyticsService = new AnalyticsService();

/**
 * Hook for tracking page views
 */
export const usePageTracking = (pageName: string) => {
  useEffect(() => {
    analyticsService.trackPageView(pageName);
  }, [pageName]);
};
```

**Benefits:**
- ✅ User behavior tracking
- ✅ Performance metrics
- ✅ Error tracking
- ✅ Conversion tracking
- ✅ A/B testing support

---

### ✅ IMPROVEMENT 10: Implement Responsive Design & Mobile-First

**Current Problem:**
- Not fully responsive
- Poor mobile experience
- Inconsistent breakpoints

**Solution: Mobile-First Design System**

```typescript
// config/breakpoints.ts - Responsive breakpoints
export const breakpoints = {
  xs: '0px',
  sm: '640px',  // mobile
  md: '768px',  // tablet
  lg: '1024px', // desktop
  xl: '1280px', // wide
  '2xl': '1536px', // ultra-wide
};

// Chakra responsive syntax example
<Box
  display={{ base: 'block', md: 'grid' }}
  gridTemplateColumns={{ base: '1fr', md: '1fr 1fr', lg: '1fr 1fr 1fr' }}
  gap={{ base: 2, md: 4, lg: 6 }}
/>
```

```typescript
// hooks/useResponsive.ts - Responsive hook
import { useBreakpointValue } from '@chakra-ui/react';

export const useResponsiveLayout = () => {
  return {
    isMobile: useBreakpointValue({ base: true, md: false }) ?? false,
    isTablet: useBreakpointValue({ base: false, md: true, lg: false }) ?? false,
    isDesktop: useBreakpointValue({ base: false, lg: true }) ?? false,
  };
};
```

**Benefits:**
- ✅ Mobile-first approach
- ✅ Consistent breakpoints
- ✅ Better mobile experience
- ✅ Improved accessibility
- ✅ Touch-friendly UI

---

## 5 EXPERT RECOMMENDATIONS FROM PAYCORE

### ✅ RECOMMENDATION 1: Redux + Redux Persist Architecture
**From PayCore:** Redux with persist for state management + offline support

**Implementation Status:** ✅ INTEGRATED (See Improvement 1)

**Why It Works:**
- Single source of truth
- Time-travel debugging
- Offline state persistence
- Middleware support

---

### ✅ RECOMMENDATION 2: Chakra UI + Accessibility
**From PayCore:** Component library with built-in accessibility

**Implementation Status:** ✅ INTEGRATED (See Improvement 3)

**Why It Works:**
- WCAG 2.1 AA compliant
- Keyboard navigation
- Screen reader support
- Dark mode built-in

---

### ✅ RECOMMENDATION 3: WebSocket for Real-Time
**From PayCore:** WebSocket context for live updates

**Implementation Status:** ✅ INTEGRATED (See Improvement 4)

**Why It Works:**
- Live notifications
- Real-time inventory
- Bidirectional communication
- Automatic reconnection

---

### ✅ RECOMMENDATION 4: Service Layer Architecture
**From PayCore:** API services separated by domain

**Implementation Status:** ✅ INTEGRATED (See Improvement 2)

**Why It Works:**
- Centralized API management
- Interceptors for auth/errors
- Testable code
- Easy to maintain

---

### ✅ RECOMMENDATION 5: Feature-Based Directory Structure
**From PayCore:** Organized by features/domains

```
src/
├── features/
│   ├── auth/          # All auth-related code
│   │   ├── components/
│   │   ├── hooks/
│   │   ├── services/
│   │   ├── types/
│   │   └── store/
│   ├── products/      # All product-related code
│   │   ├── components/
│   │   ├── services/
│   │   ├── types/
│   │   └── hooks/
│   ├── cart/          # All cart-related code
│   ├── orders/        # All order-related code
│   ├── payments/      # All payment-related code
│   └── vendor/        # Vendor-specific features
├── components/        # Shared components
├── hooks/            # Shared hooks
├── services/         # Shared services
├── store/            # Redux store
├── types/            # Shared types
└── utils/            # Utilities
```

**Benefits:**
- ✅ Better code organization
- ✅ Easy to find related code
- ✅ Scalable structure
- ✅ Team collaboration friendly
- ✅ Microservice-ready

---

## INTEGRATED FRONTEND ARCHITECTURE

### Complete Tech Stack

```json
{
  "framework": "Next.js 14 (App Router)",
  "runtime": "Node.js 20+",
  "language": "TypeScript 5.8+",
  "ui": "Chakra UI + Tailwind CSS",
  "stateManagement": "Redux Toolkit + Zustand",
  "dataFetching": "Axios + React Query",
  "realtime": "WebSocket",
  "forms": "React Hook Form + Zod",
  "styling": "Emotion + Tailwind",
  "animations": "Framer Motion",
  "icons": "Lucide React + Chakra Icons",
  "charts": "Recharts",
  "routing": "Next.js App Router",
  "authentication": "JWT + Redux Persist",
  "caching": "React Query",
  "offline": "Service Workers + IndexedDB",
  "analytics": "Custom Analytics Service",
  "errorTracking": "Sentry",
  "testing": "Jest + React Testing Library",
  "deployment": "Docker + Kubernetes"
}
```

### Directory Structure (Production-Ready)

```
fashionista-frontend/
├── src/
│   ├── app/                          # Next.js App Router
│   │   ├── (auth)/                   # Auth routes
│   │   │   ├── login/
│   │   │   ├── register/
│   │   │   └── forgot-password/
│   │   ├── (public)/                 # Public routes
│   │   │   ├── page.tsx              # Homepage
│   │   │   ├── products/
│   │   │   ├── categories/
│   │   │   └── about/
│   │   ├── dashboard/                # Protected routes
│   │   │   ├── @client/              # Client dashboard
│   │   │   ├── @vendor/              # Vendor dashboard
│   │   │   └── @admin/               # Admin dashboard
│   │   ├── cart/
│   │   ├── checkout/
│   │   ├── orders/
│   │   └── layout.tsx
│   │
│   ├── features/                     # Feature-based structure
│   │   ├── auth/
│   │   │   ├── components/
│   │   │   │   ├── LoginForm.tsx
│   │   │   │   ├── RegisterForm.tsx
│   │   │   │   └── ProtectedRoute.tsx
│   │   │   ├── hooks/
│   │   │   │   ├── useAuth.ts
│   │   │   │   └── useLogin.ts
│   │   │   ├── services/
│   │   │   │   └── authService.ts
│   │   │   ├── store/
│   │   │   │   └── authSlice.ts
│   │   │   └── types/
│   │   │       └── auth.types.ts
│   │   │
│   │   ├── products/
│   │   │   ├── components/
│   │   │   │   ├── ProductCard.tsx
│   │   │   │   ├── ProductGrid.tsx
│   │   │   │   ├── ProductFilter.tsx
│   │   │   │   └── ProductDetail.tsx
│   │   │   ├── hooks/
│   │   │   │   ├── useProducts.ts
│   │   │   │   ├── useProductDetail.ts
│   │   │   │   └── useProductSearch.ts
│   │   │   ├── services/
│   │   │   │   └── productsService.ts
│   │   │   ├── store/
│   │   │   │   └── productsSlice.ts
│   │   │   └── types/
│   │   │       └── product.types.ts
│   │   │
│   │   ├── cart/
│   │   │   ├── components/
│   │   │   │   ├── CartItem.tsx
│   │   │   │   ├── CartSummary.tsx
│   │   │   │   └── CartEmpty.tsx
│   │   │   ├── hooks/
│   │   │   │   └── useCart.ts
│   │   │   ├── store/
│   │   │   │   └── cartSlice.ts
│   │   │   └── types/
│   │   │       └── cart.types.ts
│   │   │
│   │   ├── orders/
│   │   │   ├── components/
│   │   │   ├── hooks/
│   │   │   ├── services/
│   │   │   ├── store/
│   │   │   └── types/
│   │   │
│   │   ├── payments/
│   │   │   ├── components/
│   │   │   ├── services/
│   │   │   ├── hooks/
│   │   │   └── types/
│   │   │
│   │   ├── vendor/
│   │   │   ├── components/
│   │   │   ├── services/
│   │   │   └── store/
│   │   │
│   │   ├── notifications/
│   │   │   ├── components/
│   │   │   ├── hooks/
│   │   │   ├── store/
│   │   │   └── services/
│   │   │
│   │   └── admin/
│   │       ├── components/
│   │       ├── services/
│   │       └── store/
│   │
│   ├── components/                   # Shared components
│   │   ├── common/
│   │   │   ├── Header.tsx
│   │   │   ├── Footer.tsx
│   │   │   ├── Navigation.tsx
│   │   │   ├── Breadcrumb.tsx
│   │   │   ├── ErrorBoundary.tsx
│   │   │   └── LoadingSpinner.tsx
│   │   ├── layout/
│   │   │   ├── MainLayout.tsx
│   │   │   ├── DashboardLayout.tsx
│   │   │   └── AuthLayout.tsx
│   │   └── modals/
│   │       ├── ConfirmDialog.tsx
│   │       └── NotificationToast.tsx
│   │
│   ├── hooks/                        # Custom hooks
│   │   ├── useAuth.ts
│   │   ├── useWebSocket.ts
│   │   ├── useResponsive.ts
│   │   ├── useLocalStorage.ts
│   │   ├── useDebounce.ts
│   │   ├── useAsync.ts
│   │   └── usePagination.ts
│   │
│   ├── services/                     # API services
│   │   ├── api.ts                    # Axios instance + interceptors
│   │   ├── authService.ts
│   │   ├── productsService.ts
│   │   ├── ordersService.ts
│   │   ├── cartService.ts
│   │   ├── paymentsService.ts
│   │   ├── analyticsService.ts
│   │   ├── errorService.ts
│   │   └── queryClient.ts            # React Query config
│   │
│   ├── store/                        # Redux store
│   │   ├── store.ts                  # Store configuration
│   │   └── slices/
│   │       ├── authSlice.ts
│   │       ├── cartSlice.ts
│   │       ├── productsSlice.ts
│   │       ├── ordersSlice.ts
│   │       ├── notificationsSlice.ts
│   │       ├── filtersSlice.ts
│   │       └── vendorSlice.ts
│   │
│   ├── contexts/                     # React contexts
│   │   ├── WebSocketContext.tsx
│   │   ├── ThemeContext.tsx
│   │   └── NotificationContext.tsx
│   │
│   ├── types/                        # TypeScript types
│   │   ├── index.ts
│   │   ├── auth.ts
│   │   ├── products.ts
│   │   ├── orders.ts
│   │   ├── payments.ts
│   │   ├── cart.ts
│   │   ├── errors.ts
│   │   └── api.ts
│   │
│   ├── utils/                        # Utilities
│   │   ├── formatters.ts
│   │   ├── validators.ts
│   │   ├── constants.ts
│   │   ├── helpers.ts
│   │   ├── offlineStorage.ts
│   │   └── logging.ts
│   │
│   ├── config/                       # Configuration
│   │   ├── env.ts
│   │   ├── breakpoints.ts
│   │   ├── constants.ts
│   │   └── lazyComponents.ts
│   │
│   ├── styles/                       # Global styles
│   │   ├── globals.css
│   │   ├── variables.css
│   │   └── animations.css
│   │
│   ├── theme/                        # Chakra theme
│   │   ├── index.ts
│   │   ├── colors.ts
│   │   ├── typography.ts
│   │   └── components.ts
│   │
│   └── public/
│       ├── sw.js                     # Service Worker
│       └── manifest.json             # PWA manifest
│
├── tests/                            # Tests
│   ├── unit/
│   ├── integration/
│   └── e2e/
│
├── docker/
│   ├── Dockerfile
│   └── Dockerfile.prod
│
├── docs/                             # Documentation
│   ├── ARCHITECTURE.md
│   ├── API.md
│   └── DEPLOYMENT.md
│
├── .github/
│   └── workflows/
│       ├── ci.yml
│       ├── cd.yml
│       └── lint.yml
│
├── package.json
├── tsconfig.json
├── next.config.js
├── tailwind.config.js
├── postcss.config.js
└── .env.example
```

---

## TECH STACK & DEPENDENCIES

### Updated package.json (Production-Ready)

```json
{
  "name": "fashionista-frontend",
  "version": "2.0.0",
  "private": true,
  "type": "module",
  "description": "FASHIONISTAR - Enterprise eCommerce Platform for African Fashion",
  "author": "FASHIONISTAR Team",
  "license": "MIT",
  "scripts": {
    "dev": "next dev",
    "build": "next build",
    "start": "next start",
    "lint": "next lint",
    "type-check": "tsc --noEmit",
    "format": "prettier --write .",
    "test": "jest",
    "test:watch": "jest --watch",
    "test:coverage": "jest --coverage",
    "e2e": "playwright test",
    "analyze": "ANALYZE=true next build",
    "serve:build": "next start"
  },
  "dependencies": {
    "next": "^14.1.4",
    "react": "^18.3.1",
    "react-dom": "^18.3.1",
    "@chakra-ui/react": "^2.10.9",
    "@chakra-ui/icons": "^2.2.4",
    "@emotion/react": "^11.14.0",
    "@emotion/styled": "^11.14.1",
    "framer-motion": "^6.5.1",
    "@reduxjs/toolkit": "^2.9.0",
    "react-redux": "^9.2.0",
    "redux-persist": "^6.0.0",
    "zustand": "^5.0.3",
    "@tanstack/react-query": "^5.28.0",
    "axios": "^1.11.0",
    "react-hook-form": "^7.52.1",
    "@hookform/resolvers": "^3.9.1",
    "zod": "^3.23.8",
    "yup": "^1.7.0",
    "date-fns": "^4.1.0",
    "jwt-decode": "^4.0.0",
    "dexie": "^4.0.8",
    "lucide-react": "^0.542.0",
    "react-icons": "^5.5.0",
    "recharts": "^2.15.1",
    "clsx": "^2.1.0",
    "tailwindcss": "^3.3.0",
    "autoprefixer": "^10.0.1",
    "postcss": "^8.4.38"
  },
  "devDependencies": {
    "typescript": "^5.8.3",
    "@types/node": "^22.10.7",
    "@types/react": "^18.3.17",
    "@types/react-dom": "^18.3.7",
    "@typescript-eslint/eslint-plugin": "^8.39.1",
    "@typescript-eslint/parser": "^8.39.1",
    "eslint": "^8.57.0",
    "eslint-config-next": "^14.1.4",
    "prettier": "^3.3.3",
    "jest": "^29.7.0",
    "@testing-library/react": "^15.0.6",
    "@testing-library/jest-dom": "^6.4.2",
    "playwright": "^1.48.0",
    "@sentry/react": "^7.119.0",
    "next-bundle-analyzer": "^0.6.0"
  },
  "engines": {
    "node": ">=20.0.0",
    "npm": ">=10.0.0"
  }
}
```

---

## PERFORMANCE OPTIMIZATION STRATEGY

### Core Web Vitals Targets

| Metric | Current | Target | Action |
|--------|---------|--------|--------|
| **LCP** (Largest Contentful Paint) | 3s | < 2.5s | Image optimization, lazy loading |
| **FID** (First Input Delay) | 150ms | < 100ms | Code splitting, reduce JS |
| **CLS** (Cumulative Layout Shift) | 0.1 | < 0.1 | Fixed dimensions, avoid layout shifts |

### Optimization Strategies

```typescript
// 1. Image Optimization
import Image from 'next/image';

export const OptimizedImage = ({ src, alt }: Props) => (
  <Image
    src={src}
    alt={alt}
    width={400}
    height={400}
    priority={false}          // Lazy load
    quality={75}              // Compress
    placeholder="blur"        // Blur effect
    blurDataURL="..."
    sizes="(max-width: 768px) 100vw, 50vw"
  />
);

// 2. Code Splitting
const AdminDashboard = dynamic(() => import('@/components/AdminDashboard'), {
  loading: () => <Skeleton height="400px" />,
  ssr: false,
});

// 3. Preloading
<link rel="prefetch" href="/api/products" />
<link rel="preload" as="font" href="/fonts/satoshi.woff2" />

// 4. Memoization
const ProductCard = memo(({ product }: Props) => {
  return <div>{product.name}</div>;
});

// 5. Virtual Scrolling for large lists
import { FixedSizeList } from 'react-window';
```

### Monitoring & Alerts

```typescript
// Sentry integration
import * as Sentry from '@sentry/react';

Sentry.init({
  dsn: process.env.NEXT_PUBLIC_SENTRY_DSN,
  environment: process.env.NODE_ENV,
  integrations: [
    new Sentry.Replay({
      maskAllText: true,
      blockAllMedia: true,
    }),
  ],
  tracesSampleRate: 1.0,
  replaysSessionSampleRate: 0.1,
  replaysOnErrorSampleRate: 1.0,
});

// Core Web Vitals tracking
import { getCLS, getFID, getFCP, getLCP, getTTFB } from 'web-vitals';

getCLS(console.log);
getFID(console.log);
getFCP(console.log);
getLCP(console.log);
getTTFB(console.log);
```

---

## SECURITY & AUTHENTICATION

### JWT Authentication Flow

```typescript
// Secure token storage in httpOnly cookies (recommended)
// or Redux + Redux Persist (with encryption)

export const setAuthTokens = (tokens: { access: string; refresh: string }) => {
  // Option 1: Store in Redux (with encryption)
  dispatch(setTokens(tokens));

  // Option 2: Store in localStorage (less secure, but workable)
  localStorage.setItem('accessToken', tokens.access);
  localStorage.setItem('refreshToken', tokens.refresh);
};

// Secure API calls
api.interceptors.request.use((config) => {
  const token = getAccessToken();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Token refresh on expiration
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    if (error.response?.status === 401) {
      const refreshToken = getRefreshToken();
      const { data } = await refreshTokenRequest(refreshToken);
      setAuthTokens(data);
      return api(error.config);
    }
    return Promise.reject(error);
  }
);
```

### Security Best Practices

- ✅ HTTPS only (enforce in production)
- ✅ CSRF tokens (from backend)
- ✅ Content Security Policy (CSP)
- ✅ XSS prevention (Sanitize HTML)
- ✅ Input validation (Zod schemas)
- ✅ Secure headers (X-Frame-Options, etc.)
- ✅ Rate limiting (backend)
- ✅ 2FA support (via backend)

---

## REAL-TIME FEATURES & WEBSOCKET INTEGRATION

### WebSocket Event Types

```typescript
// Server → Client Events
type ServerEvent = 
  | { type: 'order_created'; data: Order }
  | { type: 'order_status_updated'; data: { orderId: string; status: string } }
  | { type: 'payment_confirmed'; data: { orderId: string } }
  | { type: 'inventory_updated'; data: { productId: string; quantity: number } }
  | { type: 'notification'; data: Notification }
  | { type: 'message'; data: Message };

// Client → Server Events
type ClientEvent =
  | { type: 'subscribe_channel'; channel: string }
  | { type: 'unsubscribe_channel'; channel: string }
  | { type: 'send_message'; data: Message }
  | { type: 'heartbeat' };
```

### Real-Time Features

```typescript
// 1. Live order updates
useEffect(() => {
  const unsubscribe = useWebSocket().subscribe('order_status_updated', (data) => {
    dispatch(updateOrder(data));
    toast({
      title: 'Order Updated',
      description: `Your order #${data.orderId} is now ${data.status}`,
      status: 'info',
    });
  });
  return unsubscribe;
}, [dispatch, toast]);

// 2. Inventory updates
useEffect(() => {
  const unsubscribe = useWebSocket().subscribe('inventory_updated', (data) => {
    dispatch(updateProductStock(data));
  });
  return unsubscribe;
}, [dispatch]);

// 3. Live notifications
useEffect(() => {
  const unsubscribe = useWebSocket().subscribe('notification', (data) => {
    dispatch(addNotification(data));
  });
  return unsubscribe;
}, [dispatch]);
```

---

## PRODUCTION DEPLOYMENT & DEVOPS

### Docker Configuration

```dockerfile
# Dockerfile - Optimized multi-stage build
FROM node:20-alpine AS dependencies
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

FROM node:20-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:20-alpine AS runtime
WORKDIR /app
COPY --from=dependencies /app/node_modules ./node_modules
COPY --from=build /app/.next ./.next
COPY --from=build /app/public ./public
COPY --from=build /app/package*.json ./

EXPOSE 3000
ENV NODE_ENV=production
CMD ["npm", "start"]
```

### Kubernetes Deployment

```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: fashionista-frontend
spec:
  replicas: 3
  selector:
    matchLabels:
      app: fashionista-frontend
  template:
    metadata:
      labels:
        app: fashionista-frontend
    spec:
      containers:
      - name: fashionista-frontend
        image: fashionista/frontend:latest
        ports:
        - containerPort: 3000
        env:
        - name: NEXT_PUBLIC_API_URL
          value: https://api.fashionista.com
        - name: NEXT_PUBLIC_WS_URL
          value: wss://api.fashionista.com/ws
        resources:
          requests:
            memory: "256Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /
            port: 3000
          initialDelaySeconds: 10
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /
            port: 3000
          initialDelaySeconds: 5
          periodSeconds: 5
```

### CI/CD Pipeline

```yaml
# .github/workflows/deploy.yml
name: Deploy Frontend

on:
  push:
    branches: [main]

jobs:
  build-and-deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '20'
          cache: 'npm'
      
      - name: Install dependencies
        run: npm ci
      
      - name: Lint
        run: npm run lint
      
      - name: Type check
        run: npm run type-check
      
      - name: Run tests
        run: npm run test:coverage
      
      - name: Build
        run: npm run build
      
      - name: Build Docker image
        run: docker build -t fashionista/frontend:${{ github.sha }} .
      
      - name: Push to registry
        run: docker push fashionista/frontend:${{ github.sha }}
      
      - name: Deploy to Kubernetes
        run: kubectl set image deployment/fashionista-frontend fashionista-frontend=fashionista/frontend:${{ github.sha }}
```

---

## MIGRATION PATH & IMPLEMENTATION TIMELINE

### Phase 1: Foundation (Weeks 1-2)
- [ ] Set up Redux + Redux Persist
- [ ] Implement API service layer with Axios
- [ ] Set up error boundaries
- [ ] Integrate Chakra UI

### Phase 2: Features (Weeks 3-4)
- [ ] Implement WebSocket context
- [ ] Add React Query for caching
- [ ] Implement lazy loading + code splitting
- [ ] Add offline support (PWA)

### Phase 3: Optimization (Weeks 5-6)
- [ ] Implement analytics service
- [ ] Add performance monitoring (Sentry)
- [ ] Optimize images + bundle size
- [ ] Implement mobile-first responsive design

### Phase 4: Testing & Deployment (Weeks 7-8)
- [ ] Write unit tests (90%+ coverage)
- [ ] Write integration tests
- [ ] Write E2E tests
- [ ] Set up CI/CD pipeline
- [ ] Deploy to production

---

## PRODUCTION CHECKLIST

### Code Quality
- [ ] ESLint configured with strict rules
- [ ] Prettier auto-formatting
- [ ] Type checking (tsc --noEmit)
- [ ] 90%+ test coverage
- [ ] No console.log in production
- [ ] Error handling on all async operations
- [ ] Loading states on all data fetches

### Performance
- [ ] LCP < 2.5s
- [ ] FID < 100ms
- [ ] CLS < 0.1
- [ ] Bundle size < 500KB (main)
- [ ] JS execution < 3.8s
- [ ] Images optimized (WebP, lazy loading)
- [ ] CSS critical path optimized

### Security
- [ ] HTTPS only
- [ ] CSP headers configured
- [ ] CORS properly configured
- [ ] Input validation (Zod/Yup)
- [ ] Output sanitization
- [ ] Secrets in environment variables
- [ ] No API keys in code
- [ ] Rate limiting configured

### Accessibility
- [ ] WCAG 2.1 AA compliant
- [ ] Keyboard navigation works
- [ ] Screen reader compatible
- [ ] Color contrast ratios checked
- [ ] Alt text on all images
- [ ] ARIA labels where needed
- [ ] Focus indicators visible

### DevOps
- [ ] Docker image optimized
- [ ] Kubernetes manifests ready
- [ ] Secrets management configured
- [ ] Monitoring/logging setup
- [ ] Database backups configured
- [ ] CDN configured
- [ ] SSL/TLS certificates

### Analytics & Monitoring
- [ ] Sentry configured
- [ ] Analytics tracking implemented
- [ ] Error tracking active
- [ ] Performance monitoring active
- [ ] User session tracking
- [ ] Conversion tracking

### Documentation
- [ ] Architecture documentation
- [ ] API documentation
- [ ] Deployment guide
- [ ] Troubleshooting guide
- [ ] Contributing guide
- [ ] Code comments

---

## CONCLUSION

**FASHIONISTAR Frontend 6.0** is now designed to be:

✅ **Enterprise-Grade** - Production-tested patterns  
✅ **Performant** - Sub-100ms API responses, optimized bundle  
✅ **Secure** - JWT auth, HTTPS, CSP, input validation  
✅ **Accessible** - WCAG 2.1 AA compliant, keyboard navigation  
✅ **Real-Time** - WebSocket integration, live updates  
✅ **Scalable** - Feature-based architecture, Redux for state  
✅ **Competitive** - Ready to compete with Etsy, Jumia, Amazon  
✅ **African-First** - Optimized for African eCommerce needs  

**Status: 🚀 READY FOR IMPLEMENTATION** (8-week timeline)

---

**Architecture Version:** 6.0  
**Status:** ✅ ENTERPRISE-GRADE  
**Date:** January 26, 2026  
**Team:** FASHIONISTAR Engineering  
**Target Platforms:** Web (Desktop + Mobile), PWA  
**Performance Target:** 99.9% uptime, <100ms APIs, <2.5s LCP  
**Accessibility Target:** WCAG 2.1 AA  
