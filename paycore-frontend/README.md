# PayCore Frontend

A comprehensive, production-ready fintech platform frontend built with React, TypeScript, Vite, Chakra UI, and Redux Toolkit.

> **⚠️ Important Notice**: The live backend server will be discontinued on **February 14th, 2026** due to hosting costs. This is a demonstration project. The frontend will gracefully display a friendly error message when the server becomes unreachable. You can run both projects locally following the setup instructions.

> **📊 Performance Note**: The live URL may experience slower response times. This is **not** due to the application or implementation itself, but rather the hosting service configuration. The free/basic tier uses limited RAM and server resources. For optimal performance, please run the project locally using the setup instructions below.

## 🔗 Related Projects

- **Backend API**: [kayprogrammer/paycore-api-1](https://github.com/kayprogrammer/paycore-api-1)
- **Live Demo**: [https://paycore-fe.netlify.app](https://paycore-fe.netlify.app)

## 📸 Screenshots

### Login Page (Google OAuth)
![PayCore Login Page](public/display1.png?v=2)

### Dashboard
![PayCore Dashboard](public/display2.png?v=2)

## 🚀 Features

PayCore is a complete financial services platform that consumes **137 API endpoints** across **13 modules**:

### Core Financial Services
- 💰 **Wallets** - Multi-currency wallet management with virtual account numbers
- 💳 **Cards** - Virtual and physical card issuance and management
- 🔄 **Transactions** - Transfers, deposits, withdrawals, and disputes
- 📱 **Bill Payments** - Airtime, data, electricity, cable TV, and more
- 💵 **Payment Links & Invoices** - Merchant payment solutions
- 🏦 **Loans** - Personal, business, payday, and student loans with auto-repayment
- 📈 **Investments** - Fixed deposits, bonds, mutual funds, stocks, real estate

### Additional Features
- 🎫 **Support** - Ticketing system and FAQs
- 🔒 **Compliance** - KYC verification with multi-tier levels
- 🔔 **Notifications** - Real-time push and in-app notifications
- 📊 **Audit Logs** - Complete activity tracking
- 👤 **Profile Management** - User profiles with avatar upload
- ⚙️ **Settings** - Security, notifications, devices, and account management

### Authentication & Security
- 🌐 **Google OAuth** - Primary authentication method (Sign in with Google)
- 📧 **Email/OTP** - Alternative authentication with OTP verification
- 🔄 **JWT Token Management** - Auto-refresh with secure storage
- 📱 **Multi-device Support** - Session management across devices
- 🛡️ **PIN-based Authorization** - Transaction security with wallet PINs

## 🏗️ Architecture

### Modular Microservice Pattern

The project follows a feature-based modular architecture, where each feature is organized like a microservice:

```
src/
├── features/
│   ├── auth/
│   │   ├── components/
│   │   ├── services/     # RTK Query API
│   │   ├── types/        # TypeScript interfaces
│   │   ├── hooks/        # Custom hooks
│   │   └── utils/        # Feature utilities
│   ├── wallets/
│   ├── cards/
│   ├── transactions/
│   ├── bills/
│   ├── payments/
│   ├── loans/
│   ├── investments/
│   ├── support/
│   ├── compliance/
│   ├── notifications/
│   ├── audit/
│   └── profile/
├── components/
│   ├── common/           # Reusable components
│   ├── layout/           # Layouts (MainLayout, AuthLayout)
│   ├── ui/               # UI components
│   └── forms/            # Form components
├── pages/                # Page components
├── store/                # Redux store
│   ├── api/              # RTK Query base API
│   └── slices/           # Redux slices
├── hooks/                # Global hooks
├── services/             # API services
├── types/                # Global types
├── utils/                # Utilities
├── theme/                # Chakra UI theme
└── assets/               # Static assets
```

## 🛠️ Tech Stack

### Core
- **React 18** - UI library
- **TypeScript** - Type safety
- **Vite** - Build tool
- **React Router v7** - Routing

### State Management
- **Redux Toolkit** - State management
- **RTK Query** - API integration and caching

### UI & Styling
- **Chakra UI** - Component library
- **Emotion** - CSS-in-JS
- **Framer Motion** - Animations
- **React Icons** - Icons
- **Recharts** - Data visualization

### Forms & Validation
- **React Hook Form** - Form management
- **Yup** - Schema validation

### Utilities
- **Axios** - HTTP client
- **date-fns** - Date utilities
- **jwt-decode** - JWT token decoding

## 📦 Installation & Setup

### Prerequisites
- **Node.js 20.19+ or 22.12+** and npm (for local development, required by Vite 7.x)
- **Docker & Docker Compose** (for containerized deployment)
- **Backend API** running (Django PayCore API)
- **Google OAuth Client ID** (for authentication)

### Option 1: Quick Start with Makefile (Recommended)

```bash
# Navigate to project
cd /Users/mac/Documents/Projects/ViteJs/paycore-frontend

# Quick start for development
make quick-start

# Or for production with Docker
make quick-prod
```

### Option 2: Manual Setup

#### Local Development

1. **Navigate to the repository**
```bash
cd /Users/mac/Documents/Projects/ViteJs/paycore-frontend
```

2. **Install dependencies**
```bash
npm install
# Or using Makefile
make install
```

3. **Configure environment variables**
```bash
cp .env.example .env.development
# Or using Makefile
make env-example
```

Edit `.env.development`:
```env
VITE_API_BASE_URL=http://localhost:8000/api/v1
VITE_APP_NAME=PayCore
VITE_GOOGLE_CLIENT_ID=your_google_oauth_client_id
```

4. **Start development server**
```bash
npm run dev
# Or using Makefile
make dev
```

The app will be available at `http://localhost:3000`

#### Docker Development

```bash
# Build and run development container with hot reload
make docker-dev

# Or manually
docker-compose -f docker-compose.dev.yml up
```

#### Docker Production

```bash
# Build production image
make docker-build

# Run production container
make docker-run

# Or build and run in one command
make quick-prod

# Or manually
docker-compose up -d
```

The app will be available at `http://localhost:3000`

## 🧪 Available Commands

### NPM Scripts

```bash
npm run dev          # Start development server
npm run build        # Build for production
npm run preview      # Preview production build
npm run lint         # Run ESLint
npm run type-check   # TypeScript type checking
```

### Makefile Commands

```bash
# Development
make dev             # Start development server
make build           # Build for production
make clean           # Clean build artifacts
make install         # Install dependencies

# Code Quality
make lint            # Run ESLint
make lint-fix        # Run ESLint with auto-fix
make type-check      # TypeScript type checking
make format          # Format code with Prettier

# Docker - Production
make docker-build    # Build production Docker image
make docker-run      # Run production container
make docker-stop     # Stop production container
make docker-logs     # View container logs
make docker-shell    # Open shell in container

# Docker - Development
make docker-dev      # Run dev container with hot reload
make docker-dev-stop # Stop development container
make docker-dev-logs # View dev container logs

# Utilities
make help            # Show all available commands
make info            # Display project information
make backend-check   # Check if backend is running
```

See full command list with: `make help`

## 📝 API Coverage

### Complete Endpoint Implementation

| Module | Endpoints | Status |
|--------|-----------|--------|
| Authentication | 13 | ✅ Complete |
| Profile | 3 | ✅ Complete |
| Wallets | 19 | ✅ Complete |
| Cards | 12 | ✅ Complete |
| Transactions | 14 | ✅ Complete |
| Bills | 7 | ✅ Complete |
| Payments | 16 | ✅ Complete |
| Loans | 20 | ✅ Complete |
| Investments | 10 | ✅ Complete |
| Support | 9 | ✅ Complete |
| Compliance | 4 | ✅ Complete |
| Notifications | 4 | ✅ Complete |
| Audit Logs | 3 | ✅ Complete |
| **Total** | **137** | **✅ 100%** |

## 🎨 Design System

### Theme

Custom Chakra UI theme with brand colors:

```typescript
brand: {
  50: '#EEF2FF',
  500: '#6366F1',  // Primary
  600: '#4F46E5',
  900: '#312E81',
}
```

### Key Components

- Modern sidebar navigation with active states
- Header with notifications and user menu
- Custom button styles with brand colors
- Card components with shadows and hover effects
- Input fields with focus states
- Toast notifications for feedback
- Modal dialogs for forms
- Responsive breakpoints (sm, md, lg, xl, 2xl)

## 🔐 Authentication Flow

### Primary Authentication (Google OAuth)

1. **Click "Sign in with Google"** → Google OAuth popup
2. **Authorize** → Select Google account
3. **Token Exchange** → Google ID token sent to backend
4. **Profile Fetch** → User profile and tokens received
5. **Auto-Login** → Redirect to dashboard

### Alternative Authentication (Email/OTP)

1. **Login** → Enter email → OTP sent to email
2. **Verify OTP** → Enter 6-digit code → Tokens received
3. **Token Storage** → Access & refresh tokens stored in Redux + localStorage
4. **Auto-Refresh** → Expired tokens automatically refreshed
5. **Protected Routes** → Redirect to login if not authenticated

### Key Features

- **Single Source of Truth** → Profile data fetched directly from API endpoint
- **RTK Query Caching** → Automatic cache management and invalidation
- **Real-time Updates** → Avatar and profile changes reflect immediately
- **Redux Persistence** → Auth state persists across page reloads

## 🚨 Server Unavailability Handling

When the backend server is unreachable (discontinued, network issues, etc.), the app displays a friendly error screen instead of confusing error messages.

### How It Works

1. **Health Check on Load** → App checks server availability when it loads (5-second timeout)
2. **Server Unreachable** → Shows friendly screen with crying emoji 😢 immediately
3. **Server Available** → App loads normally
4. **Backup Detection** → If server goes down during usage, also caught by API interceptor

### User Experience

Instead of seeing:
```
❌ Google Login Failed
❌ Could not sign in with Google
❌ CORS errors in console
```

Users see:
```
😢
Server Unavailable

The PayCore API server has been stopped and is now unreachable.
This was a demonstration project hosted on a paid server.
The live server was discontinued on February 14th, 2026.

[Try Again Button]
[View Backend Repository Button]

You can run the project locally by following the setup instructions in the repository.
```

### Implementation

- **Health Check Hook**: `src/hooks/useHealthCheck.ts` - Runs on app load
- **Error Detection**: `src/utils/errorHandlers.ts` - Detects network/server errors
- **UI Component**: `src/components/common/ServerUnavailable.tsx` - Friendly error screen
- **Redux State**: `src/store/slices/serverStatusSlice.ts` - Tracks server status

## 📊 State Management

### Redux Store Structure

```typescript
{
  api: RTKQueryState,     // All API cache
  auth: {
    user: User | null,
    accessToken: string | null,
    refreshToken: string | null,
    isAuthenticated: boolean,
  },
  serverStatus: {
    isServerAvailable: boolean,
    lastChecked: number | null,
  }
}
```

### RTK Query Features

- Automatic cache management with tags
- Optimistic updates
- Automatic refetching on focus/reconnect
- Request deduplication
- Polling support

## 🔌 API Integration

All API services are created using RTK Query with automatic:
- Token injection in headers
- Token refresh on 401 errors
- Error handling
- Loading states
- Cache invalidation

### Example Usage

```typescript
import { useListWalletsQuery } from '@/features/wallets/services/walletsApi';

function WalletsPage() {
  const { data, isLoading, error } = useListWalletsQuery();

  if (isLoading) return <LoadingSpinner />;
  if (error) return <ErrorAlert message="Failed to load" />;

  return <WalletsList wallets={data.data.items} />;
}
```

## 🌐 Pages Overview

### Authentication Pages
- **LoginPage** - Google OAuth sign-in (primary method)
- **RegisterPage** - Google OAuth sign-up (primary method)
- **VerifyOTPPage** - 6-digit OTP verification (alternative method)
- **ForgotPasswordPage** - Multi-step password reset

### Main Application Pages
- **DashboardPage** - Overview with charts and quick actions
- **WalletsPage** - Wallet management with security settings
- **CardsPage** - Card display and controls
- **TransactionsPage** - Transaction history with filters
- **BillsPage** - Bill payment interface
- **LoansPage** - Loan marketplace and management
- **InvestmentsPage** - Investment portfolio
- **ProfilePage** - User profile and KYC
- **SettingsPage** - Security and preferences

## 🔧 Utilities

### Formatters (`src/utils/formatters.ts`)

```typescript
formatCurrency(50000, 'NGN')  // ₦50,000.00
formatDate('2024-01-01')      // Jan 01, 2024
formatRelativeTime(date)      // 2 hours ago
maskCardNumber(cardNumber)    // 5399 **** **** 1234
getStatusColor('completed')   // 'green'
```

## 📈 Data Visualization

Charts implemented using Recharts:

- **Line Charts** - Transaction trends
- **Area Charts** - Balance over time
- **Pie Charts** - Portfolio distribution
- **Bar Charts** - Monthly comparisons

## 📱 Responsive Design

- Mobile-first approach
- Sidebar becomes drawer on mobile
- Responsive tables with horizontal scroll
- Stack layouts on small screens
- Touch-friendly buttons and inputs

## 🚧 Development Guidelines

### Adding a New Feature

1. Create types in `src/features/[feature]/types/index.ts`
2. Create RTK Query API in `src/features/[feature]/services/[feature]Api.ts`
3. Build components in `src/features/[feature]/components/`
4. Create page in `src/pages/[feature]/`
5. Add route in `App.tsx`
6. Update sidebar navigation if needed

### Code Style

- Use TypeScript for type safety
- Follow existing naming conventions
- Use Chakra UI components
- Implement proper error handling
- Add loading states everywhere
- Use formatters for display
- Write clean, readable code

## 🔒 Security Features

- ✅ **Google OAuth Integration** - Secure third-party authentication
- ✅ **JWT Tokens** - Auto-refresh mechanism for seamless sessions
- ✅ **Secure Token Storage** - Redux Persist with localStorage
- ✅ **PIN Authorization** - Transaction-level security
- ✅ **Data Masking** - Sensitive data (card numbers, etc.)
- ✅ **Input Validation** - Client-side form validation
- ✅ **Protected Routes** - Authentication guards
- ✅ **Multi-factor Authentication** - OTP verification
- ✅ **Profile Security** - Avatar upload, password management removed (Google-only auth)

## 🐳 Docker Deployment

### Quick Docker Commands

```bash
# Development with hot reload
make docker-dev

# Production deployment
make docker-build
make docker-run

# View logs
make docker-logs

# Stop containers
make docker-stop
```

### Docker Images

**Production Image (Multi-stage build):**
- Based on `node:20-alpine` (builder) + `nginx:alpine` (runtime)
- Optimized for production with minimal size
- Includes Nginx for serving static files
- Health checks configured
- Security headers enabled
- Gzip compression enabled

**Development Image:**
- Based on `node:20-alpine`
- Hot reload enabled with Vite HMR
- Volume mounting for live code updates
- Full development tooling
- Accessible at http://localhost:3000

### Docker Compose

**Production:**
```bash
docker-compose up -d
```

**Development:**
```bash
docker-compose -f docker-compose.dev.yml up
```

### Environment Variables in Docker

Set in `docker-compose.yml` or via command line:

```bash
docker build \
  --build-arg VITE_API_BASE_URL=https://api.paycore.com/api/v1 \
  --build-arg VITE_GOOGLE_CLIENT_ID=your_google_client_id \
  -t paycore-frontend:latest .
```

**Required Environment Variables:**
- `VITE_API_BASE_URL` - Backend API URL
- `VITE_GOOGLE_CLIENT_ID` - Google OAuth Client ID
- `VITE_APP_NAME` - Application name (default: PayCore)

**Port Configuration:**
- **Development**: Container port 5173 → Host port 3000
- **Production**: Container port 80 → Host port (configurable in docker-compose.yml)

### Container Management

```bash
# View running containers
docker ps

# View logs
docker logs -f paycore-frontend

# Open shell in container
docker exec -it paycore-frontend sh

# Restart container
docker restart paycore-frontend

# Remove container
docker rm -f paycore-frontend
```

## 🎯 Production Deployment

### Option 1: Docker (Recommended)

```bash
# Build and deploy with Docker
make docker-build
make docker-run

# Or use docker-compose
docker-compose up -d
```

### Option 2: Traditional Build

```bash
# Build for production
npm run build
# Or
make build
```

Output in `dist/` folder (optimized, minified, code-split)

### Environment Variables for Production

Create `.env.production`:
```env
VITE_API_BASE_URL=https://api.paycore.com/api/v1
VITE_APP_NAME=PayCore
VITE_GOOGLE_CLIENT_ID=your_google_client_id
```

### Deployment Platforms

#### Vercel (Recommended for non-Docker)
```bash
npm install -g vercel
vercel --prod
# Or
make deploy-vercel
```

#### Netlify
```bash
npm install -g netlify-cli
netlify deploy --prod --dir=dist
# Or
make deploy-netlify
```

**Important for Netlify**: The project includes a `_redirects` file in the `public/` folder and `netlify.toml` at the root to handle SPA routing. This ensures that direct URL access (like `/dashboard`, `/login`) works correctly by serving `index.html` for all routes.

**Files for Netlify:**
- `public/_redirects` - Redirect configuration
- `netlify.toml` - Netlify configuration (alternative to `_redirects`)

If you encounter 404 errors when accessing routes directly, ensure these files are committed to your repository.

#### AWS S3 + CloudFront
```bash
# Build first
npm run build

# Upload to S3
aws s3 sync dist/ s3://your-bucket-name

# Invalidate CloudFront cache
aws cloudfront create-invalidation --distribution-id YOUR_DIST_ID --paths "/*"
```

#### Docker Swarm
```bash
docker stack deploy -c docker-compose.yml paycore
```

#### Kubernetes
```bash
# Create deployment and service
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
```

### Nginx Configuration

The production Docker image uses Nginx with:
- Gzip compression
- Security headers (X-Frame-Options, X-Content-Type-Options, etc.)
- SPA routing support
- Static asset caching (1 year)
- Health check endpoint at `/health`

## 🎯 Quick Start Guide

### Authentication Methods

**Primary Method: Google OAuth**
- Click "Sign in with Google" button
- Authorize with your Google account
- Instant access to dashboard

**Alternative Method: Email/OTP**
- Enter your email address
- Receive 6-digit OTP via email
- Verify OTP to access dashboard

**Note**: Password-based authentication and change password functionality have been removed in favor of Google OAuth for enhanced security.

### Quick Navigation

| Page | URL | Description |
|------|-----|-------------|
| Dashboard | `/dashboard` | Overview, wallet summary, charts |
| Wallets | `/wallets` | Manage multi-currency wallets |
| Cards | `/cards` | Virtual/physical card management |
| Transactions | `/transactions` | Transfer, deposit, withdraw |
| Bills | `/bills` | Pay airtime, data, electricity, etc. |
| Loans | `/loans` | Apply for loans, repayment |
| Investments | `/investments` | Investment portfolio |
| Profile | `/profile` | Edit profile, KYC verification |
| Settings | `/settings` | Security, notifications |

### Key Features to Try

#### 1. Wallet Operations
```bash
# Create Wallet: Dashboard → "Add Wallet" → Select currency
# Set PIN: Wallets → Click wallet → Security → "Set PIN"
# View Balance: Toggle eye icon to show/hide balance
```

#### 2. Transfers
```bash
# Send Money: Transactions → "Transfer" → Enter details + PIN
# Receive: Share your wallet account number
```

#### 3. Card Management
```bash
# Create Card: Cards → "Create Card" → Choose virtual/physical
# Fund Card: Click card → "Fund Card" → Enter amount + PIN
# Freeze Card: Click card menu → "Freeze Card"
```

#### 4. Bill Payments
```bash
# Pay Bills: Bills → Select category → Choose provider → Enter details
# View History: Bills → "Payment History"
```

#### 5. Loans
```bash
# Calculate: Loans → Calculator → Adjust sliders
# Apply: Loans → "Apply for Loan" → Fill form
# Repay: Active loans → "Make Repayment"
```

#### 6. Investments
```bash
# Invest: Investments → "Create Investment" → Choose product
# Portfolio: View charts and performance metrics
# Liquidate: Active investment → "Liquidate" (if needed)
```

## 🐛 Troubleshooting

### Common Issues

**Problem**: "Failed to fetch" errors
**Solution**:
- Ensure Django backend is running on port 8000
- Check `VITE_API_BASE_URL` in `.env.development`
- Verify CORS settings in Django

**Problem**: Login works but gets logged out immediately
**Solution**:
- Check browser console for errors
- Verify tokens are being saved (check Redux DevTools)
- Clear localStorage and try again

**Problem**: OTP not working
**Solution**:
- Check Django terminal for OTP code
- OTP expires after 10 minutes
- Request new OTP if needed

**Problem**: Styles not loading
**Solution**:
```bash
# Clear Vite cache and restart
rm -rf node_modules/.vite
make dev
```

**Problem**: TypeScript errors
**Solution**:
```bash
# Run type check
make type-check

# Most errors are auto-fixed by restarting dev server
```

## 📦 Project Statistics

- **Total Files Created**: 120+
- **Total Lines of Code**: ~18,000+
- **API Endpoints Consumed**: 137/137 (100%)
- **RTK Query Hooks**: 137
- **Type Definitions**: 60+ interfaces
- **Pages**: 17 (4 auth + 13 main)
- **Features**: 13 modules
- **Dependencies**: 36 production, 14 dev
- **Docker Images**: 2 (production + development)
- **Makefile Commands**: 50+

## 🔍 API Endpoint Verification

All **137 endpoints** from the Django PayCore API have been properly consumed:

| Module | Endpoints | Implementation |
|--------|-----------|----------------|
| Authentication | 13 | ✅ `src/features/auth/services/authApi.ts` |
| Profile | 3 | ✅ `src/features/profile/services/profileApi.ts` |
| Wallets | 19 | ✅ `src/features/wallets/services/walletsApi.ts` |
| Cards | 12 | ✅ `src/features/cards/services/cardsApi.ts` |
| Transactions | 14 | ✅ `src/features/transactions/services/transactionsApi.ts` |
| Bills | 7 | ✅ `src/features/bills/services/billsApi.ts` |
| Payments | 16 | ✅ `src/features/payments/services/paymentsApi.ts` |
| Loans | 20 | ✅ `src/features/loans/services/loansApi.ts` |
| Investments | 10 | ✅ `src/features/investments/services/investmentsApi.ts` |
| Support | 9 | ✅ `src/features/support/services/supportApi.ts` |
| Compliance | 4 | ✅ `src/features/compliance/services/complianceApi.ts` |
| Notifications | 4 | ✅ `src/features/notifications/services/notificationsApi.ts` |
| Audit Logs | 3 | ✅ `src/features/audit/services/auditApi.ts` |

**All endpoints are fully functional with:**
- ✅ RTK Query hooks
- ✅ TypeScript type definitions
- ✅ Cache management
- ✅ Error handling
- ✅ Loading states
- ✅ UI integration

## 👥 Credits

- **Author**: Kenechi Ifeanyi
- **License**: MIT
- **Backend**: Django PayCore API
- **Version**: 1.0.0

## 📚 External Documentation

- [Chakra UI](https://chakra-ui.com/) - Component library
- [Redux Toolkit](https://redux-toolkit.js.org/) - State management
- [RTK Query](https://redux-toolkit.js.org/rtk-query/overview) - API integration
- [React Router](https://reactrouter.com/) - Routing
- [Vite](https://vitejs.dev/) - Build tool
- [TypeScript](https://www.typescriptlang.org/) - Type safety

## 📞 Support

For issues or questions:
- Check the Makefile commands: `make help`
- View backend status: `make backend-check`
- Review logs: `make docker-logs` (for Docker) or check browser console

---

**✅ PayCore Frontend - Production Ready**
**Built with ❤️ for modern fintech solutions**
**100% API Coverage | Fully Dockerized | Comprehensive Documentation**
