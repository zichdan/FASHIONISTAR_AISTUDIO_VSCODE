import { baseApi } from '@/store/api/baseApi';
import type { ApiResponse, PaginatedResponse, QueryParams } from '@/types/common';
import type {
  Card,
  CreateCardRequest,
  UpdateCardRequest,
  FundCardRequest,
  UpdateCardControlsRequest,
  CardTransaction,
} from '../types';

export const cardsApi = baseApi.injectEndpoints({
  endpoints: (builder) => ({
    // 1. Create Card
    createCard: builder.mutation<ApiResponse<Card>, CreateCardRequest>({
      query: (data) => ({
        url: '/cards/create',
        method: 'POST',
        body: data,
      }),
      invalidatesTags: ['Cards'],
    }),

    // 2. List Cards
    listCards: builder.query<ApiResponse<Card[]>, { status?: string; card_type?: string } | void>({
      query: (params) => ({
        url: '/cards/list',
        params: params || undefined,
      }),
      providesTags: ['Cards'],
    }),

    // 3. Get Card
    getCard: builder.query<ApiResponse<Card>, string>({
      query: (id) => `/cards/card/${id}`,
      providesTags: ['Cards'],
    }),

    // 4. Update Card
    updateCard: builder.mutation<ApiResponse<Card>, { id: string; data: UpdateCardRequest }>({
      query: ({ id, data}) => ({
        url: `/cards/card/${id}`,
        method: 'PATCH',
        body: data,
      }),
      invalidatesTags: ['Cards'],
    }),

    // 5. Delete Card
    deleteCard: builder.mutation<ApiResponse<null>, string>({
      query: (id) => ({
        url: `/cards/card/${id}`,
        method: 'DELETE',
      }),
      invalidatesTags: ['Cards'],
    }),

    // 6. Fund Card
    fundCard: builder.mutation<ApiResponse<Card>, { cardId: string; data: FundCardRequest }>({
      query: ({ cardId, data }) => ({
        url: `/cards/card/${cardId}/fund`,
        method: 'POST',
        body: data,
      }),
      invalidatesTags: ['Cards', 'Wallets'],
    }),

    // 7. Freeze Card
    freezeCard: builder.mutation<ApiResponse<Card>, string>({
      query: (cardId) => ({
        url: `/cards/card/${cardId}/freeze`,
        method: 'POST',
      }),
      invalidatesTags: ['Cards'],
    }),

    // 8. Unfreeze Card
    unfreezeCard: builder.mutation<ApiResponse<Card>, string>({
      query: (cardId) => ({
        url: `/cards/card/${cardId}/unfreeze`,
        method: 'POST',
      }),
      invalidatesTags: ['Cards'],
    }),

    // 9. Block Card
    blockCard: builder.mutation<ApiResponse<Card>, string>({
      query: (cardId) => ({
        url: `/cards/card/${cardId}/block`,
        method: 'POST',
      }),
      invalidatesTags: ['Cards'],
    }),

    // 10. Activate Card
    activateCard: builder.mutation<ApiResponse<Card>, string>({
      query: (cardId) => ({
        url: `/cards/card/${cardId}/activate`,
        method: 'POST',
      }),
      invalidatesTags: ['Cards'],
    }),

    // 11. Update Card Controls
    updateCardControls: builder.mutation<
      ApiResponse<Card>,
      { cardId: string; data: UpdateCardControlsRequest }
    >({
      query: ({ cardId, data }) => ({
        url: `/cards/card/${cardId}/controls`,
        method: 'PATCH',
        body: data,
      }),
      invalidatesTags: ['Cards'],
    }),

    // 12. Get Card Transactions
    getCardTransactions: builder.query<
      ApiResponse<PaginatedResponse<CardTransaction>>,
      { cardId: string; params?: QueryParams }
    >({
      query: ({ cardId, params }) => ({
        url: `/cards/card/${cardId}/transactions`,
        params,
      }),
      providesTags: ['Cards', 'Transactions'],
    }),
  }),
});

export const {
  useCreateCardMutation,
  useListCardsQuery,
  useGetCardQuery,
  useUpdateCardMutation,
  useDeleteCardMutation,
  useFundCardMutation,
  useFreezeCardMutation,
  useUnfreezeCardMutation,
  useBlockCardMutation,
  useActivateCardMutation,
  useUpdateCardControlsMutation,
  useGetCardTransactionsQuery,
} = cardsApi;
