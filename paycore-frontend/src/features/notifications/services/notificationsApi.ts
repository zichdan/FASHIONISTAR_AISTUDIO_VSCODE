import { baseApi } from '@/store/api/baseApi';
import type { ApiResponse, PaginatedResponse, QueryParams } from '@/types/common';
import type {
  Notification,
  NotificationStatistics,
  MarkAsReadRequest,
} from '../types';

export const notificationsApi = baseApi.injectEndpoints({
  endpoints: (builder) => ({
    // 1. List Notifications
    listNotifications: builder.query<
      ApiResponse<PaginatedResponse<Notification>>,
      QueryParams | void
    >({
      query: (params) => ({
        url: '/notifications',
        params,
      }),
      providesTags: ['Notifications'],
    }),

    // 2. Get Notification Statistics
    getNotificationStatistics: builder.query<ApiResponse<NotificationStatistics>, void>({
      query: () => '/notifications/statistics',
      providesTags: ['Notifications'],
    }),

    // 3. Mark as Read
    markAsRead: builder.mutation<ApiResponse<{ message: string }>, MarkAsReadRequest>({
      query: (data) => ({
        url: '/notifications/mark-read',
        method: 'POST',
        body: data,
      }),
      invalidatesTags: ['Notifications'],
    }),

    // 4. Delete Notifications
    deleteNotifications: builder.mutation<ApiResponse<{ message: string }>, string[]>({
      query: (notification_ids) => ({
        url: '/notifications',
        method: 'DELETE',
        body: { notification_ids },
      }),
      invalidatesTags: ['Notifications'],
    }),
  }),
});

export const {
  useListNotificationsQuery,
  useGetNotificationStatisticsQuery,
  useMarkAsReadMutation,
  useDeleteNotificationsMutation,
} = notificationsApi;
