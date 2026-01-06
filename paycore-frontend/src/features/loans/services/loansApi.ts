import { baseApi } from '@/store/api/baseApi';
import type { ApiResponse, PaginatedResponse, QueryParams } from '@/types/common';
import type {
  LoanProduct,
  LoanApplication,
  CreateLoanApplicationRequest,
  CalculateLoanRequest,
  CalculateLoanResponse,
  LoanRepaymentSchedule,
  MakeRepaymentRequest,
  LoanRepayment,
  AutoRepaymentSettings,
  EnableAutoRepaymentRequest,
  CreditScore,
  LoanSummary,
} from '../types';

export const loansApi = baseApi.injectEndpoints({
  endpoints: (builder) => ({
    // 1. List Loan Products
    listLoanProducts: builder.query<ApiResponse<LoanProduct[]>, { type?: string }>({
      query: (params) => ({
        url: '/loans/products/list',
        params,
      }),
      providesTags: ['Loans'],
    }),

    // 2. Get Loan Product
    getLoanProduct: builder.query<ApiResponse<LoanProduct>, string>({
      query: (id) => `/loans/products/product/${id}`,
      providesTags: ['Loans'],
    }),

    // 3. Calculate Loan
    calculateLoan: builder.mutation<ApiResponse<CalculateLoanResponse>, CalculateLoanRequest>({
      query: (data) => ({
        url: '/loans/calculate',
        method: 'POST',
        params: data,
      }),
    }),

    // 4. Create Loan Application
    createLoanApplication: builder.mutation<
      ApiResponse<LoanApplication>,
      CreateLoanApplicationRequest
    >({
      query: (data) => ({
        url: '/loans/applications/create',
        method: 'POST',
        body: data,
      }),
      invalidatesTags: ['Loans'],
    }),

    // 5. List Loan Applications
    listLoanApplications: builder.query<
      ApiResponse<PaginatedResponse<LoanApplication>>,
      QueryParams | void
    >({
      query: (params) => ({
        url: '/loans/applications/list',
        params,
      }),
      providesTags: ['Loans'],
    }),

    // 6. Get Loan Application
    getLoanApplication: builder.query<ApiResponse<LoanApplication>, string>({
      query: (id) => `/loans/applications/application/${id}`,
      providesTags: ['Loans'],
    }),

    // 7. Cancel Loan Application
    cancelLoanApplication: builder.mutation<ApiResponse<LoanApplication>, string>({
      query: (id) => ({
        url: `/loans/applications/application/${id}/cancel`,
        method: 'POST',
      }),
      invalidatesTags: ['Loans'],
    }),

    // 8. Get Repayment Schedule
    getRepaymentSchedule: builder.query<ApiResponse<LoanRepaymentSchedule[]>, string>({
      query: (loanId) => `/loans/applications/${loanId}/schedule`,
      providesTags: ['Loans'],
    }),

    // 9. Make Repayment
    makeRepayment: builder.mutation<ApiResponse<LoanRepayment>, MakeRepaymentRequest>({
      query: (data) => ({
        url: `/loans/applications/${data.application_id}/repay`,
        method: 'POST',
        body: data,
      }),
      invalidatesTags: ['Loans', 'Wallets', 'Transactions'],
    }),

    // 10. Get Repayment History
    getRepaymentHistory: builder.query<
      ApiResponse<PaginatedResponse<LoanRepayment>>,
      { loanId: string; params?: QueryParams }
    >({
      query: ({ loanId, params }) => ({
        url: `/loans/applications/application/${loanId}/repayments`,
        params,
      }),
      providesTags: ['Loans'],
    }),

    // 11. Enable Auto Repayment
    enableAutoRepayment: builder.mutation<
      ApiResponse<AutoRepaymentSettings>,
      EnableAutoRepaymentRequest
    >({
      query: (data) => ({
        url: '/loans/auto-repayment/enable',
        method: 'POST',
        body: data,
      }),
      invalidatesTags: ['Loans'],
    }),

    // 12. Get Auto Repayment Settings
    getAutoRepaymentSettings: builder.query<ApiResponse<AutoRepaymentSettings>, string>({
      query: (loanId) => `/loans/auto-repayment/${loanId}`,
      providesTags: ['Loans'],
    }),

    // 13. Update Auto Repayment Settings
    updateAutoRepaymentSettings: builder.mutation<
      ApiResponse<AutoRepaymentSettings>,
      { loanId: string; wallet_id: string }
    >({
      query: ({ loanId, wallet_id }) => ({
        url: `/loans/auto-repayment/${loanId}`,
        method: 'PUT',
        body: { wallet_id },
      }),
      invalidatesTags: ['Loans'],
    }),

    // 14. Disable Auto Repayment
    disableAutoRepayment: builder.mutation<ApiResponse<{ message: string }>, string>({
      query: (loanId) => ({
        url: `/loans/auto-repayment/${loanId}/disable`,
        method: 'POST',
      }),
      invalidatesTags: ['Loans'],
    }),

    // 15. Suspend Auto Repayment
    suspendAutoRepayment: builder.mutation<
      ApiResponse<AutoRepaymentSettings>,
      { loanId: string; suspended_until: string }
    >({
      query: ({ loanId, suspended_until }) => ({
        url: `/loans/auto-repayment/${loanId}/suspend`,
        method: 'POST',
        body: { suspended_until },
      }),
      invalidatesTags: ['Loans'],
    }),

    // 16. Reactivate Auto Repayment
    reactivateAutoRepayment: builder.mutation<ApiResponse<AutoRepaymentSettings>, string>({
      query: (loanId) => ({
        url: `/loans/auto-repayment/${loanId}/reactivate`,
        method: 'POST',
      }),
      invalidatesTags: ['Loans'],
    }),

    // 17. Get Credit Score
    getCreditScore: builder.query<ApiResponse<CreditScore>, void>({
      query: () => '/loans/credit-score',
      providesTags: ['Loans'],
    }),

    // 18. Refresh Credit Score
    refreshCreditScore: builder.mutation<ApiResponse<CreditScore>, void>({
      query: () => ({
        url: '/loans/credit-score/refresh',
        method: 'POST',
      }),
      invalidatesTags: ['Loans'],
    }),

    // 19. Get Loan Summary
    getLoanSummary: builder.query<ApiResponse<LoanSummary>, void>({
      query: () => '/loans/summary',
      providesTags: ['Loans'],
    }),

    // 20. Get Loan Details
    getLoanDetails: builder.query<
      ApiResponse<LoanApplication & { repayment_schedule: LoanRepaymentSchedule[] }>,
      string
    >({
      query: (loanId) => `/loans/applications/application/${loanId}/details`,
      providesTags: ['Loans'],
    }),
  }),
});

export const {
  useListLoanProductsQuery,
  useGetLoanProductQuery,
  useCalculateLoanMutation,
  useCreateLoanApplicationMutation,
  useListLoanApplicationsQuery,
  useGetLoanApplicationQuery,
  useCancelLoanApplicationMutation,
  useGetRepaymentScheduleQuery,
  useMakeRepaymentMutation,
  useGetRepaymentHistoryQuery,
  useEnableAutoRepaymentMutation,
  useGetAutoRepaymentSettingsQuery,
  useUpdateAutoRepaymentSettingsMutation,
  useDisableAutoRepaymentMutation,
  useSuspendAutoRepaymentMutation,
  useReactivateAutoRepaymentMutation,
  useGetCreditScoreQuery,
  useRefreshCreditScoreMutation,
  useGetLoanSummaryQuery,
  useGetLoanDetailsQuery,
} = loansApi;
