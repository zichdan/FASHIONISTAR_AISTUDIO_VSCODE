import { baseApi } from '@/store/api/baseApi';
import type { ApiResponse, PaginatedResponse, QueryParams } from '@/types/common';
import type {
  Ticket,
  CreateTicketRequest,
  TicketMessage,
  AddMessageRequest,
  RateTicketRequest,
  TicketStatistics,
  FAQ,
} from '../types';

export const supportApi = baseApi.injectEndpoints({
  endpoints: (builder) => ({
    // 1. Create Ticket
    createTicket: builder.mutation<ApiResponse<Ticket>, CreateTicketRequest>({
      query: (data) => ({
        url: '/support/tickets/create',
        method: 'POST',
        body: data,
      }),
      invalidatesTags: ['Support'],
    }),

    // 2. List Tickets
    listTickets: builder.query<ApiResponse<PaginatedResponse<Ticket>>, QueryParams | void>({
      query: (params) => ({
        url: '/support/tickets/list',
        params,
      }),
      providesTags: ['Support'],
    }),

    // 3. Get Ticket
    getTicket: builder.query<ApiResponse<Ticket>, string>({
      query: (id) => `/support/tickets/${id}`,
      providesTags: ['Support'],
    }),

    // 4. Close Ticket
    closeTicket: builder.mutation<ApiResponse<Ticket>, string>({
      query: (id) => ({
        url: `/support/tickets/${id}/close`,
        method: 'POST',
      }),
      invalidatesTags: ['Support'],
    }),

    // 5. Rate Ticket
    rateTicket: builder.mutation<
      ApiResponse<Ticket>,
      { ticketId: string; data: RateTicketRequest }
    >({
      query: ({ ticketId, data }) => ({
        url: `/support/tickets/${ticketId}/rate`,
        method: 'POST',
        body: data,
      }),
      invalidatesTags: ['Support'],
    }),

    // 6. Add Message
    addMessage: builder.mutation<
      ApiResponse<TicketMessage>,
      { ticketId: string; data: AddMessageRequest }
    >({
      query: ({ ticketId, data }) => {
        // If there are attachments, use FormData; otherwise use JSON
        if (data.attachments && data.attachments.length > 0) {
          const formData = new FormData();
          formData.append('message', data.message);
          data.attachments.forEach((file, index) => {
            formData.append(`attachments[${index}]`, file);
          });

          return {
            url: `/support/tickets/${ticketId}/messages`,
            method: 'POST',
            body: formData,
            formData: true,
          };
        } else {
          // No attachments, send as JSON
          return {
            url: `/support/tickets/${ticketId}/messages`,
            method: 'POST',
            body: { message: data.message },
          };
        }
      },
      invalidatesTags: ['Support'],
    }),

    // 7. Get Ticket Messages
    getTicketMessages: builder.query<
      ApiResponse<PaginatedResponse<TicketMessage>>,
      { ticketId: string; params?: QueryParams }
    >({
      query: ({ ticketId, params }) => ({
        url: `/support/tickets/${ticketId}/messages`,
        params,
      }),
      providesTags: ['Support'],
    }),

    // 8. Get Ticket Statistics
    getTicketStatistics: builder.query<ApiResponse<TicketStatistics>, void>({
      query: () => '/support/tickets/statistics',
      providesTags: ['Support'],
    }),

    // 9. List FAQs
    listFAQs: builder.query<ApiResponse<FAQ[]>, { category?: string } | void>({
      query: (params) => ({
        url: '/support/faq/list',
        params,
      }),
      providesTags: ['Support'],
    }),
  }),
});

export const {
  useCreateTicketMutation,
  useListTicketsQuery,
  useGetTicketQuery,
  useCloseTicketMutation,
  useRateTicketMutation,
  useAddMessageMutation,
  useGetTicketMessagesQuery,
  useGetTicketStatisticsQuery,
  useListFAQsQuery,
} = supportApi;
