import { baseApi } from '@/store/api/baseApi';
import type { ApiResponse, PaginatedResponse, QueryParams, Currency } from '@/types/common';
import type {
  Wallet,
  CreateWalletRequest,
  UpdateWalletRequest,
  WalletBalance,
  SetPinRequest,
  ChangePinRequest,
  HoldFundsRequest,
  WalletHold,
  WalletSummary,
  WalletSecurityStatus,
} from '../types';

export const walletsApi = baseApi.injectEndpoints({
  endpoints: (builder) => ({
    // 0. List Currencies
    listCurrencies: builder.query<ApiResponse<Currency[]>, void>({
      query: () => '/wallets/currencies',
      providesTags: ['Currencies'],
    }),

    // 1. Create Wallet
    createWallet: builder.mutation<ApiResponse<Wallet>, CreateWalletRequest>({
      query: (data) => ({
        url: '/wallets/create',
        method: 'POST',
        body: data,
      }),
      invalidatesTags: ['Wallets'],
    }),

    // 2. List Wallets
    listWallets: builder.query<ApiResponse<Wallet[]>, { currency_code?: string; wallet_type?: string; status?: string } | void>({
      query: (params) => ({
        url: '/wallets/list',
        params,
      }),
      providesTags: ['Wallets'],
    }),

    // 3. Get Wallet
    getWallet: builder.query<ApiResponse<Wallet>, string>({
      query: (id) => `/wallets/wallet/${id}`,
      providesTags: ['Wallets'],
    }),

    // 4. Update Wallet
    updateWallet: builder.mutation<ApiResponse<Wallet>, { id: string; data: UpdateWalletRequest }>({
      query: ({ id, data }) => ({
        url: `/wallets/wallet/${id}`,
        method: 'PUT',
        body: data,
      }),
      invalidatesTags: ['Wallets'],
    }),

    // 5. Set Default Wallet
    setDefaultWallet: builder.mutation<ApiResponse<{ message: string }>, string>({
      query: (walletId) => ({
        url: `/wallets/wallet/${walletId}/set-default`,
        method: 'POST',
      }),
      invalidatesTags: ['Wallets'],
    }),

    // 6. Change Wallet Status
    changeWalletStatus: builder.mutation<ApiResponse<{ message: string }>, { walletId: string; status: string }>({
      query: ({ walletId, status }) => ({
        url: `/wallets/wallet/${walletId}/status`,
        method: 'POST',
        body: { status },
      }),
      invalidatesTags: ['Wallets'],
    }),

    // 7. Delete Wallet
    deleteWallet: builder.mutation<ApiResponse<null>, string>({
      query: (id) => ({
        url: `/wallets/wallet/${id}`,
        method: 'DELETE',
      }),
      invalidatesTags: ['Wallets'],
    }),

    // 8. Get Balance
    getWalletBalance: builder.query<ApiResponse<WalletBalance>, string>({
      query: (id) => `/wallets/wallet/${id}/balance`,
      providesTags: ['Wallets'],
    }),

    // 9. Hold Funds
    holdFunds: builder.mutation<ApiResponse<WalletHold>, { walletId: string; data: HoldFundsRequest }>({
      query: ({ walletId, data }) => ({
        url: `/wallets/wallet/${walletId}/hold`,
        method: 'POST',
        body: data,
      }),
      invalidatesTags: ['Wallets'],
    }),

    // 10. Release Held Funds
    releaseHold: builder.mutation<ApiResponse<{ message: string }>, { walletId: string; data: { amount: string; reference: string } }>({
      query: ({ walletId, data }) => ({
        url: `/wallets/wallet/${walletId}/release`,
        method: 'POST',
        body: data,
      }),
      invalidatesTags: ['Wallets'],
    }),

    // 11. Get Summary
    getWalletSummary: builder.query<ApiResponse<WalletSummary>, void>({
      query: () => '/wallets/summary',
      providesTags: ['Wallets'],
    }),

    // 12. Verify Transaction Authorization
    verifyTransactionAuth: builder.mutation<
      ApiResponse<{ authorized: boolean }>,
      { walletId: string; data: { amount: string; pin?: string; biometric_token?: string; device_id?: string } }
    >({
      query: ({ walletId, data }) => ({
        url: `/wallets/wallet/${walletId}/auth`,
        method: 'POST',
        body: data,
      }),
    }),

    // 13. Enable Wallet Security (PIN and/or Biometric)
    enableWalletSecurity: builder.mutation<
      ApiResponse<WalletSecurityStatus>,
      { walletId: string; data: { pin: string; enable_biometric?: boolean } }
    >({
      query: ({ walletId, data }) => ({
        url: `/wallets/wallet/${walletId}/security/enable`,
        method: 'POST',
        body: data,
      }),
      invalidatesTags: ['Wallets'],
    }),

    // 14. Disable Wallet Security
    disableWalletSecurity: builder.mutation<
      ApiResponse<WalletSecurityStatus>,
      { walletId: string; data: { current_pin: string; disable_pin?: boolean; disable_biometric?: boolean } }
    >({
      query: ({ walletId, data }) => ({
        url: `/wallets/wallet/${walletId}/security/disable`,
        method: 'POST',
        body: data,
      }),
      invalidatesTags: ['Wallets'],
    }),

    // 15. Set PIN
    setPin: builder.mutation<ApiResponse<{ message: string }>, { walletId: string; data: SetPinRequest }>({
      query: ({ walletId, data }) => ({
        url: `/wallets/wallet/${walletId}/pin/set`,
        method: 'POST',
        body: data,
      }),
      invalidatesTags: ['Wallets'],
    }),

    // 16. Change PIN
    changePin: builder.mutation<ApiResponse<{ message: string }>, { walletId: string; data: ChangePinRequest }>({
      query: ({ walletId, data }) => ({
        url: `/wallets/wallet/${walletId}/pin/change`,
        method: 'POST',
        body: data,
      }),
      invalidatesTags: ['Wallets'],
    }),

    // 17. Get Security Status
    getSecurityStatus: builder.query<ApiResponse<WalletSecurityStatus>, string>({
      query: (walletId) => `/wallets/wallet/${walletId}/security`,
      providesTags: ['Wallets'],
    }),

    // 18. Process Deposit Webhook (Generic)
    processDepositWebhook: builder.mutation<
      ApiResponse<any>,
      {
        account_number: string;
        amount: string;
        sender_account_number?: string;
        sender_account_name?: string;
        sender_bank_name?: string;
        external_reference: string;
        narration?: string;
        transaction_date?: string;
        webhook_payload?: any;
      }
    >({
      query: (data) => ({
        url: '/wallets/webhooks/deposit',
        method: 'POST',
        body: data,
      }),
      invalidatesTags: ['Wallets'],
    }),

    // 19. Process Paystack Webhook
    processPaystackWebhook: builder.mutation<ApiResponse<any>, { body: any; signature: string }>({
      query: ({ body }) => ({
        url: '/wallets/webhooks/paystack',
        method: 'POST',
        body,
      }),
      invalidatesTags: ['Wallets'],
    }),
  }),
});

export const {
  useListCurrenciesQuery,
  useCreateWalletMutation,
  useListWalletsQuery,
  useGetWalletQuery,
  useUpdateWalletMutation,
  useSetDefaultWalletMutation,
  useChangeWalletStatusMutation,
  useDeleteWalletMutation,
  useGetWalletBalanceQuery,
  useHoldFundsMutation,
  useReleaseHoldMutation,
  useGetWalletSummaryQuery,
  useVerifyTransactionAuthMutation,
  useEnableWalletSecurityMutation,
  useDisableWalletSecurityMutation,
  useSetPinMutation,
  useChangePinMutation,
  useGetSecurityStatusQuery,
  useProcessDepositWebhookMutation,
  useProcessPaystackWebhookMutation,
} = walletsApi;
