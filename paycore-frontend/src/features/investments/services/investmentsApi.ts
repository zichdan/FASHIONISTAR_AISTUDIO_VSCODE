import { baseApi } from '@/store/api/baseApi';
import type { ApiResponse, PaginatedResponse, QueryParams } from '@/types/common';
import type {
  InvestmentProduct,
  Investment,
  CreateInvestmentRequest,
  CalculateReturnsRequest,
  CalculateReturnsResponse,
  LiquidateInvestmentRequest,
  LiquidationResponse,
  RenewInvestmentRequest,
  InvestmentPortfolio,
  PortfolioDetails,
} from '../types';

export const investmentsApi = baseApi.injectEndpoints({
  endpoints: (builder) => ({
    // 1. List Investment Products
    listInvestmentProducts: builder.query<
      ApiResponse<InvestmentProduct[]>,
      { type?: string; risk_level?: string }
    >({
      query: (params) => ({
        url: '/investments/products/list',
        params,
      }),
      providesTags: ['Investments'],
    }),

    // 2. Get Investment Product
    getInvestmentProduct: builder.query<ApiResponse<InvestmentProduct>, string>({
      query: (id) => `/investments/products/product/${id}`,
      providesTags: ['Investments'],
    }),

    // 3. Calculate Returns
    calculateReturns: builder.query<ApiResponse<CalculateReturnsResponse>, CalculateReturnsRequest>({
      query: (params) => ({
        url: '/investments/calculate',
        params,
      }),
    }),

    // 4. Create Investment
    createInvestment: builder.mutation<ApiResponse<Investment>, CreateInvestmentRequest>({
      query: (data) => ({
        url: '/investments/create',
        method: 'POST',
        body: data,
      }),
      invalidatesTags: ['Investments', 'Wallets'],
    }),

    // 5. List Investments
    listInvestments: builder.query<
      ApiResponse<PaginatedResponse<Investment>>,
      QueryParams | void
    >({
      query: (params) => ({
        url: '/investments/list',
        params,
      }),
      providesTags: ['Investments'],
    }),

    // 6. Get Investment
    getInvestment: builder.query<ApiResponse<Investment>, string>({
      query: (id) => `/investments/investment/${id}`,
      providesTags: ['Investments'],
    }),

    // 7. Liquidate Investment
    liquidateInvestment: builder.mutation<ApiResponse<LiquidationResponse>, LiquidateInvestmentRequest>({
      query: ({ investment_id, ...data }) => ({
        url: `/investments/investment/${investment_id}/liquidate`,
        method: 'POST',
        body: data,
      }),
      invalidatesTags: ['Investments', 'Wallets', 'Transactions'],
    }),

    // 8. Renew Investment
    renewInvestment: builder.mutation<ApiResponse<Investment>, RenewInvestmentRequest>({
      query: (data) => ({
        url: '/investments/renew',
        method: 'POST',
        body: data,
      }),
      invalidatesTags: ['Investments'],
    }),

    // 9. Get Portfolio
    getPortfolio: builder.query<ApiResponse<InvestmentPortfolio>, void>({
      query: () => '/investments/portfolio/summary',
      providesTags: ['Investments'],
    }),

    // 10. Get Portfolio Details
    getPortfolioDetails: builder.query<ApiResponse<PortfolioDetails>, void>({
      query: () => '/investments/portfolio/details',
      providesTags: ['Investments'],
    }),
  }),
});

export const {
  useListInvestmentProductsQuery,
  useGetInvestmentProductQuery,
  useCalculateReturnsQuery,
  useLazyCalculateReturnsQuery,
  useCreateInvestmentMutation,
  useListInvestmentsQuery,
  useGetInvestmentQuery,
  useLiquidateInvestmentMutation,
  useRenewInvestmentMutation,
  useGetPortfolioQuery,
  useGetPortfolioDetailsQuery,
} = investmentsApi;
