import { Routes, Route, Navigate, useLocation } from 'react-router-dom';
import { Box } from '@chakra-ui/react';
import { useAppSelector, useAppDispatch } from '@/hooks';
import { useHealthCheck } from '@/hooks/useHealthCheck';
import { usePushNotifications } from '@/hooks/usePushNotifications';
import { selectIsAuthenticated } from '@/store/slices/authSlice';
import { selectIsServerAvailable, setServerAvailable } from '@/store/slices/serverStatusSlice';
import { ServerUnavailable } from '@/components/common/ServerUnavailable';

// Layouts
import MainLayout from '@/components/layout/MainLayout';
import AuthLayout from '@/components/layout/AuthLayout';

// Auth Pages
import LoginPage from '@/pages/auth/LoginPage';
import RegisterPage from '@/pages/auth/RegisterPage';
import ForgotPasswordPage from '@/pages/auth/ForgotPasswordPage';
import VerifyOTPPage from '@/pages/auth/VerifyOTPPage';

// Dashboard & Main Pages
import { DashboardPage } from '@/pages/DashboardPage';
import { WalletsPage } from '@/pages/wallets/WalletsPage';
import { CardsPage } from '@/pages/cards/CardsPage';
import { TransactionsPage } from '@/pages/transactions/TransactionsPage';
import { BillsPage } from '@/pages/bills/BillsPage';
import { PaymentsPage } from '@/pages/payments/PaymentsPage';
import { PaymentLinkPublicPage } from '@/pages/payments/PaymentLinkPublicPage';
import { InvoicePublicPage } from '@/pages/payments/InvoicePublicPage';
import { LoansPage } from '@/pages/loans/LoansPage';
import { InvestmentsPage } from '@/pages/investments/InvestmentsPage';
import { ProfilePage } from '@/pages/profile/ProfilePage';
import { SettingsPage } from '@/pages/settings/SettingsPage';
import { SupportPage } from '@/pages/SupportPage';
import { TicketsPage } from '@/pages/TicketsPage';

// Protected Route Component
interface ProtectedRouteProps {
  children: React.ReactNode;
}

const ProtectedRoute = ({ children }: ProtectedRouteProps) => {
  const isAuthenticated = useAppSelector(selectIsAuthenticated);

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  return <>{children}</>;
};

// Public Route Component (redirect if authenticated)
const PublicRoute = ({ children }: ProtectedRouteProps) => {
  const isAuthenticated = useAppSelector(selectIsAuthenticated);
  const location = useLocation();

  if (isAuthenticated) {
    // Check if there's a 'next' parameter in the URL
    const searchParams = new URLSearchParams(location.search);
    const nextUrl = searchParams.get('next');

    console.log('PublicRoute - isAuthenticated, redirecting');
    console.log('PublicRoute - location.search:', location.search);
    console.log('PublicRoute - nextUrl:', nextUrl);

    // Redirect to the 'next' URL if it exists, otherwise go to dashboard
    return <Navigate to={nextUrl || '/dashboard'} replace />;
  }

  return <>{children}</>;
};

function App() {
  const dispatch = useAppDispatch();
  const isServerAvailable = useAppSelector(selectIsServerAvailable);

  // Perform health check when app loads
  useHealthCheck();

  // Handle foreground push notifications
  usePushNotifications();

  const handleRetry = () => {
    dispatch(setServerAvailable());
    window.location.reload();
  };

  // Show server unavailable screen if server is down
  if (!isServerAvailable) {
    return <ServerUnavailable onRetry={handleRetry} />;
  }

  return (
    <Box minH="100vh">
      <Routes>
        {/* Public Routes */}
        <Route
          path="/login"
          element={
            <PublicRoute>
              <AuthLayout>
                <LoginPage />
              </AuthLayout>
            </PublicRoute>
          }
        />
        <Route
          path="/register"
          element={
            <PublicRoute>
              <AuthLayout>
                <RegisterPage />
              </AuthLayout>
            </PublicRoute>
          }
        />
        <Route
          path="/forgot-password"
          element={
            <PublicRoute>
              <AuthLayout>
                <ForgotPasswordPage />
              </AuthLayout>
            </PublicRoute>
          }
        />
        <Route
          path="/verify-otp"
          element={
            <AuthLayout>
              <VerifyOTPPage />
            </AuthLayout>
          }
        />

        {/* Public Payment Link - View accessible to all, payment requires auth */}
        <Route path="/pay/:slug" element={<PaymentLinkPublicPage />} />

        {/* Public Invoice - View accessible to all, payment requires auth */}
        <Route path="/invoices/:invoice_number" element={<InvoicePublicPage />} />

        {/* Protected Routes */}
        <Route
          path="/dashboard"
          element={
            <ProtectedRoute>
              <MainLayout>
                <DashboardPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/wallets/*"
          element={
            <ProtectedRoute>
              <MainLayout>
                <WalletsPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/cards/*"
          element={
            <ProtectedRoute>
              <MainLayout>
                <CardsPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/transactions/*"
          element={
            <ProtectedRoute>
              <MainLayout>
                <TransactionsPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/bills/*"
          element={
            <ProtectedRoute>
              <MainLayout>
                <BillsPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/payments/*"
          element={
            <ProtectedRoute>
              <MainLayout>
                <PaymentsPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/loans/*"
          element={
            <ProtectedRoute>
              <MainLayout>
                <LoansPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/investments/*"
          element={
            <ProtectedRoute>
              <MainLayout>
                <InvestmentsPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/profile"
          element={
            <ProtectedRoute>
              <MainLayout>
                <ProfilePage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/settings"
          element={
            <ProtectedRoute>
              <MainLayout>
                <SettingsPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/support"
          element={
            <ProtectedRoute>
              <MainLayout>
                <SupportPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/tickets"
          element={
            <ProtectedRoute>
              <MainLayout>
                <TicketsPage />
              </MainLayout>
            </ProtectedRoute>
          }
        />

        {/* Default Routes */}
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </Box>
  );
}

export default App;
