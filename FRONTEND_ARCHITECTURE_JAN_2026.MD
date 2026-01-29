# FRONTEND_ARCHITECTURE_JAN_2026.MD

# 🏛️ FASHIONISTAR AI: INDUSTRIAL FRONTEND ARCHITECTURE (V7.0 - Final Enterprise Edition)

**Target Era:** 2026-2030
**Core Framework:** Next.js 15 (App Router + Turbopack)
**Language:** TypeScript 5.8+ (Strict Mode)
**Styling Engine:** Tailwind CSS v4 + Shadcn/ui
**Backend Alignment:** Django 6.0 (Sync DRF + Async Ninja Hybrid)
**State Strategy:** The "Trinity" (Server State + URL State + Client State)
**Performance Target:** Core Web Vitals < 75ms (INP), < 1.0s (LCP)

---

## 📑 TABLE OF CONTENTS

1.  [Executive Architectural Summary](#1-executive-architectural-summary)
2.  [Frontend-Backend Integration Map](#2-frontend-backend-integration-map)
3.  [Directory Structure (Feature-Sliced Design 2.0)](#3-directory-structure-feature-sliced-design-20)
4.  [The Core Pillars: Detailed Implementation](#4-the-core-pillars-detailed-implementation)
    *   4.1 [UI Component Strategy: Shadcn/ui & Utils](#41-ui-component-strategy-shadcnui--utils)
    *   4.2 [Dual-Engine API Gateway & Resilience](#42-dual-engine-api-gateway--resilience)
    *   4.3 [State Management: The Trinity Strategy](#43-state-management-the-trinity-strategy)
    *   4.4 [Data Contracts & Validation: The Zod-First Mandate](#44-data-contracts--validation-the-zod-first-mandate)
    *   4.5 [Configuration & Environment: Type-Safe Tooling](#45-configuration--environment-type-safe-tooling)
5.  [Performance & Rendering Strategy](#5-performance--rendering-strategy)
6.  [UI/UX & Design Principles](#6-uiux--design-principles)
7.  [Transactional Communications: React Email](#7-transactional-communications-react-email)
8.  [AI Integration & Streaming](#8-ai-integration--streaming)
9.  [Error Handling, Resilience & Monitoring](#9-error-handling-resilience--monitoring)
10. [Testing & Quality Assurance (QA) Strategy](#10-testing--quality-assurance-qa-strategy)
11. [Developer Experience (DevEx) & Code Quality](#11-developer-experience-devex--code-quality)
12. [Security & Compliance Layer](#12-security--compliance-layer)
13. [Production-Ready Tech Stack](#13-production-ready-tech-stack)
14. [CI/CD Pipeline & DevOps Strategy](#14-cicd-pipeline--devops-strategy)
15. [Implementation Roadmap](#15-implementation-roadmap)

---

## 1. EXECUTIVE ARCHITECTURAL SUMMARY

We are architecting a **High-Performance Distributed UI** built on the **Feature-Sliced Design (FSD) 2.0** pattern. Our architecture is defined by five non-negotiable pillars designed to out-compete existing e-commerce moguls.

**The 5 Pillars of Fashionistar V7:**
1.  **Dual-Pipeline Networking:** Strict separation of `Axios` for DRF (Transactional) and `Ky/Fetch` for Ninja (Computational/AI) APIs.
2.  **Instantaneous UX through Optimistic UI:** All user interactions provide immediate feedback, with server reconciliation happening invisibly.
3.  **URL as the Single Source of State:** We employ URL-Driven State using **Nuqs**, ensuring every application state is shareable, bookmarkable, and SEO-friendly.
4.  **Next-Gen Hybrid Rendering (PPR):** We leverage **Partial Prerendering** in Next.js 15 for instant static shells with dynamic content streams, providing the fastest possible initial load.
5.  **Industrial-Grade Resilience & Observability:** Granular error boundaries, centralized monitoring with Sentry and OpenTelemetry, and automated CI/CD quality gates ensure 99.99% uptime.

---

## 2. FRONTEND-BACKEND INTEGRATION MAP

This diagram illustrates the flow of data from the client, through our frontend infrastructure, to the dual-engine Django backend.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       CLIENT LAYER (Next.js Frontend)                       │
│                   (Browser / PWA / Native Wrapper)                          │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                  ┌────────────────────┴────────────────────┐
                  │ (Vercel Edge Network / Cloudflare)      │
                  │  - Caching Static Assets (SSG Pages)    │
                  │  - Image Optimization (next/image)      │
                  │  - Edge Functions (Middleware)          │
                  └────────────────────┬────────────────────┘
                                       │
                         ┌─────────────┴─────────────┐
                         │      API GATEWAY (BFF)      │
                         │ (Next.js API Routes)        │
                         │ - /api/v1/* (DRF Proxy)     │
                         │ - /api/v2/* (Ninja Proxy)   │
                         └─────────────┬─────────────┘
                                       │
                  ┌────────────────────┴────────────────────┐
                  │                    │                    │
                  ▼                    ▼                    ▼
┌───────────────────────────┐ ┌───────────────────────────────┐ ┌───────────────────────────┐
│ SYNC CLIENT (Axios)       │ │ ASYNC CLIENT (Ky)             │ │ REAL-TIME CLIENT          │
│ - CSRF Handling           │ │ - Streaming Support           │ │ (WebSocket / SSE)         │
│ - Token Auto-Refresh      │ │ - Auto-Retry Logic            │ │ - Live Inventory          │
│ - Circuit Breaker         │ │ - Long Timeouts (60s)         │ │ - Order Status            │
└────────────────┬──────────┘ └────────────────┬──────────────┘ └────────────────┬──────────┘
                 │                             │                                 │
                 ▼                             ▼                                 ▼
┌───────────────────────────┐ ┌───────────────────────────────┐ ┌───────────────────────────┐
│ DJANGO DRF (SYNC)         │ │ DJANGO NINJA (ASYNC)          │ │ DJANGO CHANNELS (REAL-TIME) │
│ - Auth, Orders, Payments  │ │ - AI Measurement, Search      │ │ - WebSocket Connections   │
└───────────────────────────┘ └───────────────────────────────┘ └───────────────────────────┘
```

---

## 3. DIRECTORY STRUCTURE (FEATURE-SLICED DESIGN 2.0)

This structure is mandatory for scalability and team velocity.

```text
src/
├── app/                        # ROUTING LAYER (Next.js 15 App Router)
│   ├── [locale]/               # Internationalization Wrapper
│   │   ├── (public)/           # Static Marketing Pages
│   │   ├── (shop)/             # E-Commerce Logic
│   │   ├── (auth)/             # Login, Register, OTP
│   │   └── (dashboard)/        # Secure Areas
│   └── api/                    # BFF (Backend for Frontend) Proxy
│
├── core/                       # INFRASTRUCTURE LAYER (The Engine)
│   ├── config/                 # Env vars, Constants (T3 Env)
│   ├── api/
│   │   ├── client.sync.ts      # Axios for DRF
│   │   └── client.async.ts     # Ky for Ninja
│   ├── i18n/                   # Localization dictionaries
│   ├── types/                  # Global TS Interfaces (Pydantic Generated)
│   └── monitoring/             # Sentry, OpenTelemetry Setup
│
├── components/                 # UI LAYER (Shadcn + Shared)
│   ├── ui/                     # Shadcn Primitives (Button, Input)
│   ├── shared/                 # Navbar, Footer, Loaders
│   ├── layouts/                # AppShell, AuthLayout, DashboardLayout
│   ├── animations/             # Framer Motion wrappers (FadeIn, SlideUp)
│   ├── emails/                 # React Email Templates
│   └── providers/              # React Contexts (Theme, Auth, Query)
│
├── features/                   # DOMAIN LAYER (Business Logic)
│   ├── auth/
│   │   ├── components/         # LoginForm, RegisterForm
│   │   ├── services/           # auth.service.ts
│   │   ├── store/              # auth.store.ts (Zustand)
│   │   └── schemas/            # Zod Schemas
│   └── ...                     # Other business domains (product, cart, etc.)
│
├── lib/                        # Third-party wrappers (Firebase, Stripe)
│   └── utils.ts                # cn utility
│
├── tests/                      # QUALITY ASSURANCE LAYER
│   ├── e2e/                    # Playwright End-to-End tests
│   └── unit/                   # Vitest Unit tests
│
├── public/                     # Static Assets (robots.txt, sw.js)
│
└── styles/                     # Tailwind v4 Configuration
```

---

## 4. THE CORE PILLARS: DETAILED IMPLEMENTATION

### 4.1 UI Component Strategy: Shadcn/ui & Utils
We use Shadcn/ui. The most critical piece of code to enable this is the strict `cn` utility to merge Tailwind classes without conflict.

**Implementation Code:** `src/lib/utils.ts`

```typescript
import { type ClassValue, clsx } from "clsx"
import { twMerge } from "tailwind-merge"

/**
 * Merges Tailwind classes safely, handling conflicts (e.g., pb-4 overriding p-2)
 */
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}
```

---

### 4.2 Dual-Engine API Gateway & Resilience
We explicitly decouple synchronous transactional calls from asynchronous AI streaming calls.

#### **A. Sync Client (Axios + DRF) - Industrial Grade**
*For: Auth, Orders, Payments, CRUD.*

**Implementation Code:** `src/core/api/client.sync.ts`

```typescript
import axios, { AxiosInstance, AxiosError, InternalAxiosRequestConfig } from "axios";
import { toast } from "sonner";
import { useAuthStore } from "@/features/auth/store/auth.store";

export const apiSync: AxiosInstance = axios.create({
  baseURL: process.env.NEXT_PUBLIC_API_V1_URL,
  timeout: 15000,
  withCredentials: true,
  headers: { "Content-Type": "application/json" }
});

let isRefreshing = false;
let refreshSubscribers: ((token: string) => void)[] = [];

apiSync.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    const originalRequest = error.config as InternalAxiosRequestConfig & { _retry?: boolean };
    
    // Auto-Refresh Logic
    if (error.response?.status === 401 && !originalRequest._retry) {
      if (isRefreshing) {
        return new Promise((resolve) => {
          refreshSubscribers.push((token) => {
            if(originalRequest.headers) originalRequest.headers.Authorization = `Bearer ${token}`;
            resolve(apiSync(originalRequest));
          });
        });
      }
      originalRequest._retry = true;
      isRefreshing = true;
      try {
        const { data } = await axios.post("/api/v1/auth/token/refresh/", {}, { withCredentials: true });
        const newAccessToken = data.access;
        // Update Store
        useAuthStore.getState().setToken(newAccessToken);
        // Notify subscribers
        refreshSubscribers.forEach((cb) => cb(newAccessToken));
        refreshSubscribers = [];
        if(originalRequest.headers) originalRequest.headers.Authorization = `Bearer ${newAccessToken}`;
        return apiSync(originalRequest);
      } catch (refreshError) {
        useAuthStore.getState().logout();
        window.location.href = "/auth/login";
        return Promise.reject(refreshError);
      } finally {
        isRefreshing = false;
      }
    }

    // Global Toast Error Handling
    const traceId = error.response?.headers['x-trace-id'];
    const errorMessage = (error.response?.data as any)?.detail || "System malfunction";
    toast.error("Request Failed", { description: `${errorMessage} (Trace: ${traceId || 'N/A'})` });
    
    return Promise.reject(error);
  }
);
```

#### **B. Async Client (Ky + Django Ninja) - High Performance**
*For: AI Streams, Search, Analytics.*

**Implementation Code:** `src/core/api/client.async.ts`

```typescript
import ky from "ky";

export const apiAsync = ky.create({
  prefixUrl: process.env.NEXT_PUBLIC_API_V2_URL,
  timeout: 60000, // 60s for AI ops
  retry: {
    limit: 3,
    methods: ["get", "post"],
    statusCodes: [408, 413, 429, 500, 502, 503, 504],
  },
  hooks: {
    beforeRequest: [
      request => {
        const token = window.localStorage.getItem('auth_token'); // Or from Zustand
        if (token) request.headers.set('Authorization', `Bearer ${token}`);
      }
    ]
  }
});
```

---

### 4.3 State Management: The Trinity Strategy
This is not a recommendation; it is a mandate.

#### **1. Server State (TanStack Query v5)**
**Implementation Code:** `src/components/providers/query-provider.tsx`

```typescript
'use client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { useState } from 'react'

export default function QueryProvider({ children }: { children: React.ReactNode }) {
  const [queryClient] = useState(() => new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 60 * 1000, // Data is fresh for 1 min
        retry: 1,
      },
    },
  }))

  return (
    <QueryClientProvider client={queryClient}>
      {children}
    </QueryClientProvider>
  )
}
```

#### **2. URL State (Nuqs)**
Used for filters, search terms, and tabs.

**Implementation Example:** `src/features/shop/hooks/use-product-filters.ts`

```typescript
import { useQueryState, parseAsInteger, parseAsString } from 'nuqs'

export function useProductFilters() {
  const [category, setCategory] = useQueryState('category', parseAsString.withDefault('all'))
  const [page, setPage] = useQueryState('page', parseAsInteger.withDefault(1))

  return { category, setCategory, page, setPage }
}
```

#### **3. Global Client State (Zustand)**
Used for Auth and Cart.

**Implementation Code:** `src/features/cart/store/cart.store.ts`

```typescript
import { create } from 'zustand'
import { persist } from 'zustand/middleware'

interface CartItem {
  id: string;
  qty: number;
}

interface CartState {
  items: CartItem[];
  addItem: (item: CartItem) => void;
  clearCart: () => void;
}

export const useCartStore = create<CartState>()(
  persist(
    (set) => ({
      items: [],
      addItem: (item) => set((state) => ({ items: [...state.items, item] })),
      clearCart: () => set({ items: [] }),
    }),
    { name: 'fashionistar-cart-storage' }
  )
)
```

---

### 4.4 Data Contracts & Validation: The Zod-First Mandate
We operate on a zero-trust policy.

**Implementation Code:** `src/features/auth/schemas/login.schema.ts`

```typescript
import { z } from "zod";

export const LoginSchema = z.object({
  email: z.string().email("Invalid email address"),
  password: z.string().min(8, "Password must be at least 8 characters"),
});

export type LoginPayload = z.infer<typeof LoginSchema>;

// Example usage in API Service
export const validateLoginResponse = (data: unknown) => {
  const AuthResponseSchema = z.object({
    access: z.string(),
    refresh: z.string(),
    user: z.object({ id: z.string(), email: z.string() })
  });
  return AuthResponseSchema.parse(data); // Throws if backend changes format
};
```

---

### 4.5 Configuration & Environment: Type-Safe Tooling
We mandate `@t3-oss/env-nextjs` to prevent deployment errors.

**Implementation Code:** `src/core/config/env.mjs`

```javascript
import { createEnv } from "@t3-oss/env-nextjs";
import { z } from "zod";

export const env = createEnv({
  server: {
    NODE_ENV: z.enum(["development", "test", "production"]),
    CLOUDINARY_SECRET: z.string().min(1),
  },
  client: {
    NEXT_PUBLIC_API_V1_URL: z.string().url(),
    NEXT_PUBLIC_API_V2_URL: z.string().url(),
  },
  runtimeEnv: {
    NODE_ENV: process.env.NODE_ENV,
    NEXT_PUBLIC_API_V1_URL: process.env.NEXT_PUBLIC_API_V1_URL,
    NEXT_PUBLIC_API_V2_URL: process.env.NEXT_PUBLIC_API_V2_URL,
    CLOUDINARY_SECRET: process.env.CLOUDINARY_SECRET,
  },
});
```

---

## 5. PERFORMANCE & RENDERING STRATEGY

### 5.1 Next.js 15 Partial Prerendering (PPR)
Enabled in `next.config.js`.

```javascript
/** @type {import('next').NextConfig} */
const nextConfig = {
  experimental: {
    ppr: 'incremental', // Enables Partial Prerendering
    reactCompiler: true, // Auto-memoization
  },
  images: {
    formats: ['image/avif', 'image/webp'],
    remotePatterns: [{ hostname: 'res.cloudinary.com' }],
  }
};
module.exports = nextConfig;
```

---

## 6. UI/UX & DESIGN PRINCIPLES

### 6.1 Aesthetics & Micro-interactions (Framer Motion)
Standardized animation wrapper.

**Implementation Code:** `src/components/animations/fade-in.tsx`

```typescript
'use client'
import { motion } from "framer-motion";

export const FadeIn = ({ children, delay = 0 }: { children: React.ReactNode, delay?: number }) => (
  <motion.div
    initial={{ opacity: 0, y: 10 }}
    animate={{ opacity: 1, y: 0 }}
    transition={{ duration: 0.4, delay, ease: "easeOut" }}
  >
    {children}
  </motion.div>
);
```

---

## 7. TRANSACTIONAL COMMUNICATIONS: REACT EMAIL
Email template definition.

**Implementation Code:** `src/components/emails/welcome.tsx`

```typescript
import { Html, Button, Text } from "@react-email/components";

export default function WelcomeEmail({ url }: { url: string }) {
  return (
    <Html lang="en">
      <Text>Welcome to Fashionistar AI!</Text>
      <Button href={url} style={{ background: "#000", color: "#fff", padding: "12px 20px" }}>
        Start Shopping
      </Button>
    </Html>
  );
}
```

---

## 8. AI INTEGRATION & STREAMING
Handling WASM for client-side processing.

**Implementation Concept:** `src/features/ai/utils/load-wasm.ts`

```typescript
export const loadFFmpeg = async () => {
  const { FFmpeg } = await import('@ffmpeg/ffmpeg');
  const ffmpeg = new FFmpeg();
  await ffmpeg.load({
    coreURL: '/assets/ffmpeg/ffmpeg-core.js', // Loaded from public
  });
  return ffmpeg;
};
```

---

## 9. ERROR HANDLING, RESILIENCE & MONITORING
Granular Error Boundaries.

**Implementation Code:** `src/components/shared/error-boundary.tsx`

```typescript
'use client'
import React from "react";
import { Button } from "@/components/ui/button";

class ErrorBoundary extends React.Component<{ children: React.ReactNode }, { hasError: boolean }> {
  constructor(props: any) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError() {
    return { hasError: true };
  }

  componentDidCatch(error: any, errorInfo: any) {
    console.error("Uncaught error:", error, errorInfo);
    // Send to Sentry here
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="p-6 text-center border rounded-md bg-destructive/10">
          <h2 className="text-lg font-bold">Something went wrong.</h2>
          <Button onClick={() => this.setState({ hasError: false })} className="mt-4">
            Try again
          </Button>
        </div>
      );
    }
    return this.props.children;
  }
}
export default ErrorBoundary;
```

---

## 10. TESTING & QUALITY ASSURANCE (QA) STRATEGY

### A. Unit Testing (Vitest)
**Implementation Code:** `src/features/auth/auth.test.ts`

```typescript
import { describe, it, expect } from 'vitest';
import { LoginSchema } from './schemas/login.schema';

describe('Auth Validation', () => {
  it('rejects invalid emails', () => {
    const result = LoginSchema.safeParse({ email: 'bad-email', password: 'password123' });
    expect(result.success).toBe(false);
  });
});
```

### B. E2E Testing (Playwright)
**Implementation Code:** `tests/e2e/login.spec.ts`

```typescript
import { test, expect } from '@playwright/test';

test('user can login', async ({ page }) => {
  await page.goto('/auth/login');
  await page.fill('input[name="email"]', 'user@example.com');
  await page.fill('input[name="password"]', 'securepass');
  await page.click('button[type="submit"]');
  await expect(page).toHaveURL('/dashboard');
});
```

---

## 11. DEVELOPER EXPERIENCE (DEVEX) & CODE QUALITY

### Code Conventions: No Barrel Files
We enforce specific imports.
*   ❌ `import { Button } from "@/components/ui"` (Avoid Barrel files for tree shaking)
*   ✅ `import { Button } from "@/components/ui/button"`

---

## 12. SECURITY & COMPLIANCE LAYER
Middleware implementation for security.

**Implementation Code:** `src/middleware.ts`

```typescript
import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'

export function middleware(request: NextRequest) {
  const response = NextResponse.next();
  
  // CSP Headers
  response.headers.set(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self' 'unsafe-eval' 'unsafe-inline'; img-src 'self' res.cloudinary.com data:;"
  );

  return response;
}

export const config = {
  matcher: '/:path*',
}
```

---

## 13. PRODUCTION-READY TECH STACK & DEPENDENCIES
| Category          | Library                       | Purpose                                           |
| :---------------- | :---------------------------- | :------------------------------------------------ |
| **Core**          | `next`, `react`, `typescript` | Framework, UI Library, Language                   |
| **State & Data**  | `zustand`, `@tanstack/react-query`, `nuqs` | Client, Server, and URL State Management          |
| **UI & Styling**  | `tailwindcss`, `shadcn/ui`, `radix-ui` | Styling, Component Primitives, Accessibility      |
| **Animation**     | `framer-motion`               | Micro-interactions & Page Transitions             |
| **Forms**         | `react-hook-form`, `zod`      | Form state management, Schema validation          |
| **Notifications** | `sonner`                      | Elegant and accessible toast notifications        |

---

## 14. CI/CD PIPELINE & DEVOPS STRATEGY

### A. CI/CD Pipeline
The pipeline is enhanced with mandatory QA gates.

```
┌──────────────────┐   ┌──────────────────┐   ┌──────────────────┐   ┌──────────────────┐
│   COMMIT (PR)    │──▶│   STATIC ANALYSIS│──▶│   BUILD & TEST   │──▶│   REVIEW/MERGE   │
│ - Run Git Hooks  │   │ - ESLint         │   │ - next build     │   │ - Manual Approval│
└──────────────────┘   │ - Prettier       │   │ - Vitest (Unit)  │   └─────────┬────────┘
                       │ - A11y Check     │   └──────────────────┘             │
                       └──────────────────┘                                      │
                                                                                 ▼
                                                                 ┌───────────────┴───────────────┐
                                                                 │       DEPLOY (Staging)        │
                                                                 │ - Deploy to Staging Env       │
                                                                 │ - Run Playwright (E2E Tests)  │
                                                                 └───────────────┬───────────────┘
                                                                                 │
                                                                                 ▼
                                                                 ┌───────────────┴───────────────┐
                                                                 │      DEPLOY (Production)      │
                                                                 │ - Canary Rollout (10%)        │
                                                                 │ - Monitor Sentry/Vercel       │
                                                                 │ - Promote to 100%             │
                                                                 └───────────────────────────────┘
```

---

## 15. IMPLEMENTATION ROADMAP & PRODUCTION CHECKLIST

### Phase 1: Foundation (Days 1-3)
- [ ] Initialize Next.js 15 + TS.
- [ ] Setup Tailwind v4 + Shadcn/ui CLI.
- [ ] Create `core/api/client.sync.ts` & `client.async.ts` (Use code in Section 4.2).
- [ ] Configure `t3-env` for variable validation (Use code in Section 4.5).

### Phase 2: Core Systems (Days 4-7)
- [ ] Install TanStack Query, Zustand, Nuqs.
- [ ] Implement `QueryProvider` (Use code in Section 4.3).
- [ ] Configure Next.js middleware for CSP (Use code in Section 12).

### Phase 3: Features & Aesthetics (Days 8-14)
- [ ] Implement Auth Service with Zod schemas (Use code in Section 4.4).
- [ ] Build Login/Register forms.
- [ ] Build Product Listing with Infinite Scroll.
- [ ] Implement `Framer Motion` animations (Use code in Section 6.1).

### Phase 4: Advanced Features & Polish (Days 15-20)
- [ ] Implement AI Measurement widget with camera access.
- [ ] Integrate Firebase FCM for notifications.
- [ ] Add Sentry for error tracking.
- [ ] Run Lighthouse Audits (Target: 95+).

---
**Status:** READY FOR DEVELOPMENT  
**Version:** 7.0 Final Enterprise Edition  
**Signed Off By:** Lead Architect DANIEL EZICHI 