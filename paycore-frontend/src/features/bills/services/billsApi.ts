import { baseApi } from '@/store/api/baseApi';
import type { ApiResponse, PaginatedResponse, QueryParams } from '@/types/common';
import type {
  BillProvider,
  BillPackage,
  ValidateCustomerRequest,
  ValidateCustomerResponse,
  PayBillRequest,
  BillPayment,
} from '../types';

export const billsApi = baseApi.injectEndpoints({
  endpoints: (builder) => ({
    // 1. List Providers
    listProviders: builder.query<
      ApiResponse<BillProvider[]>,
      { category?: string; country?: string }
    >({
      query: (params) => ({
        url: '/bills/providers',
        params,
      }),
      providesTags: ['Bills'],
    }),

    // 2. Get Provider
    getProvider: builder.query<ApiResponse<BillProvider>, string>({
      query: (id) => `/bills/providers/provider/${id}`,
      providesTags: ['Bills'],
    }),

    // 3. List Packages
    listPackages: builder.query<ApiResponse<BillPackage[]>, string>({
      query: (providerId) => `/bills/providers/provider/${providerId}/packages`,
      providesTags: ['Bills'],
    }),

    // 4. Validate Customer
    validateCustomer: builder.mutation<ApiResponse<ValidateCustomerResponse>, ValidateCustomerRequest>({
      query: (data) => ({
        url: '/bills/validate-customer',
        method: 'POST',
        body: data,
      }),
    }),

    // 5. Pay Bill
    payBill: builder.mutation<ApiResponse<BillPayment>, PayBillRequest>({
      query: (data) => ({
        url: '/bills/pay',
        method: 'POST',
        body: data,
      }),
      invalidatesTags: ['Bills', 'Wallets', 'Transactions'],
    }),

    // 6. List Bill Payments
    listBillPayments: builder.query<ApiResponse<PaginatedResponse<BillPayment>>, QueryParams | void>({
      query: (params) => ({
        url: '/bills/payments',
        params,
      }),
      providesTags: ['Bills'],
    }),

    // 7. Get Bill Payment
    getBillPayment: builder.query<ApiResponse<BillPayment>, string>({
      query: (id) => `/bills/payments/payment/${id}`,
      providesTags: ['Bills'],
    }),
  }),
});

export const {
  useListProvidersQuery,
  useGetProviderQuery,
  useListPackagesQuery,
  useValidateCustomerMutation,
  usePayBillMutation,
  useListBillPaymentsQuery,
  useGetBillPaymentQuery,
} = billsApi;
