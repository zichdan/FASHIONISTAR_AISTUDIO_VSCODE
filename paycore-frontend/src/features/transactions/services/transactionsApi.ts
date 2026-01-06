import { baseApi } from '@/store/api/baseApi';
import type { ApiResponse, PaginatedResponse, QueryParams } from '@/types/common';
import type {
  Transaction,
  TransferRequest,
  TransferResponse,
  InitiateDepositRequest,
  InitiateDepositResponse,
  InitiateWithdrawalRequest,
  WithdrawalResponse,
  BankAccount,
  Bank,
  TransactionStatistics,
  Dispute,
  CreateDisputeRequest,
} from '../types';

export const transactionsApi = baseApi.injectEndpoints({
  endpoints: (builder) => ({
    // 1. Transfer
    transfer: builder.mutation<ApiResponse<TransferResponse>, TransferRequest>({
      query: (data) => ({
        url: '/transactions/transfer',
        method: 'POST',
        body: data,
      }),
      invalidatesTags: ['Transactions', 'Wallets'],
    }),

    // 2. List Transactions
    listTransactions: builder.query<ApiResponse<PaginatedResponse<Transaction>>, QueryParams | void>({
      query: (params) => ({
        url: '/transactions/list',
        params: params || undefined,
      }),
      providesTags: ['Transactions'],
    }),

    // 3. Get Transaction
    getTransaction: builder.query<ApiResponse<Transaction>, string>({
      query: (id) => `/transactions/transaction/${id}`,
      providesTags: ['Transactions'],
    }),

    // 4. Get Wallet Transactions
    getWalletTransactions: builder.query<
      ApiResponse<PaginatedResponse<Transaction>>,
      { walletId: string; params?: QueryParams }
    >({
      query: ({ walletId, params }) => ({
        url: `/transactions/wallet/${walletId}/transactions`,
        params: params || undefined,
      }),
      providesTags: ['Transactions'],
    }),

    // 5. Get Transaction Statistics
    getTransactionStatistics: builder.query<ApiResponse<TransactionStatistics>, void>({
      query: () => '/transactions/stats',
      providesTags: ['Transactions'],
    }),

    // 6. Initiate Deposit
    initiateDeposit: builder.mutation<ApiResponse<InitiateDepositResponse>, InitiateDepositRequest>({
      query: (data) => ({
        url: '/transactions/deposit/initiate',
        method: 'POST',
        body: data,
      }),
      invalidatesTags: ['Transactions'],
    }),

    // 7. Verify Deposit
    verifyDeposit: builder.query<ApiResponse<Transaction>, string>({
      query: (reference) => `/transactions/deposit/verify/${reference}`,
      providesTags: ['Transactions'],
    }),

    // 8. Initiate Withdrawal
    initiateWithdrawal: builder.mutation<ApiResponse<WithdrawalResponse>, InitiateWithdrawalRequest>({
      query: (data) => ({
        url: '/transactions/withdrawal/initiate',
        method: 'POST',
        body: data,
      }),
      invalidatesTags: ['Transactions', 'Wallets'],
    }),

    // 9. Verify Withdrawal
    verifyWithdrawal: builder.mutation<
      ApiResponse<Transaction>,
      { transaction_id?: string; reference?: string }
    >({
      query: (data) => ({
        url: '/transactions/withdrawal/verify',
        method: 'POST',
        body: data,
      }),
      invalidatesTags: ['Transactions', 'Wallets'],
    }),

    // 10. Get Withdrawal Banks
    getWithdrawalBanks: builder.query<ApiResponse<{ currency: string; banks: Bank[]; count: number }>, string | void>({
      query: (currency_code = 'NGN') => ({
        url: '/transactions/withdrawal/banks',
        params: { currency_code },
      }),
    }),

    // 11. Verify Bank Account
    verifyBankAccount: builder.mutation<
      ApiResponse<BankAccount>,
      { account_number: string; bank_code: string; currency_code?: string }
    >({
      query: ({ account_number, bank_code, currency_code = 'NGN' }) => ({
        url: '/transactions/withdrawal/verify-account',
        method: 'POST',
        params: { account_number, bank_code, currency_code },
      }),
    }),

    // 12. Create Dispute
    createDispute: builder.mutation<ApiResponse<Dispute>, { transactionId: string; data: CreateDisputeRequest }>({
      query: ({ transactionId, data }) => ({
        url: `/transactions/transaction/${transactionId}/dispute`,
        method: 'POST',
        body: data,
      }),
      invalidatesTags: ['Transactions'],
    }),

    // 13. List Disputes
    listDisputes: builder.query<ApiResponse<PaginatedResponse<Dispute>>, { status?: string; page_params?: QueryParams }>({
      query: (params) => ({
        url: '/transactions/disputes/list',
        params: params || undefined,
      }),
      providesTags: ['Transactions'],
    }),

    // 14. Get Dispute
    getDispute: builder.query<ApiResponse<Dispute>, string>({
      query: (id) => `/transactions/disputes/${id}`,
      providesTags: ['Transactions'],
    }),
  }),
});

export const {
  useTransferMutation,
  useListTransactionsQuery,
  useGetTransactionQuery,
  useGetWalletTransactionsQuery,
  useGetTransactionStatisticsQuery,
  useInitiateDepositMutation,
  useLazyVerifyDepositQuery,
  useVerifyDepositQuery,
  useInitiateWithdrawalMutation,
  useVerifyWithdrawalMutation,
  useGetWithdrawalBanksQuery,
  useVerifyBankAccountMutation,
  useCreateDisputeMutation,
  useListDisputesQuery,
  useGetDisputeQuery,
} = transactionsApi;
