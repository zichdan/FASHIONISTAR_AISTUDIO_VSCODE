import { baseApi } from '@/store/api/baseApi';
import type { ApiResponse, PaginatedResponse, QueryParams } from '@/types/common';
import type {
  AuditLog,
  AuditLogStatistics,
} from '../types';

export const auditApi = baseApi.injectEndpoints({
  endpoints: (builder) => ({
    // 1. List Audit Logs
    listAuditLogs: builder.query<
      ApiResponse<PaginatedResponse<AuditLog>>,
      QueryParams | void
    >({
      query: (params) => ({
        url: '/audit/logs',
        params,
      }),
      providesTags: ['AuditLogs'],
    }),

    // 2. Get Audit Log
    getAuditLog: builder.query<ApiResponse<AuditLog>, string>({
      query: (id) => `/audit/logs/log/${id}`,
      providesTags: ['AuditLogs'],
    }),

    // 3. Get Audit Statistics
    getAuditStatistics: builder.query<
      ApiResponse<AuditLogStatistics>,
      { start_date?: string; end_date?: string }
    >({
      query: (params) => ({
        url: '/audit/statistics',
        params,
      }),
      providesTags: ['AuditLogs'],
    }),
  }),
});

export const {
  useListAuditLogsQuery,
  useGetAuditLogQuery,
  useGetAuditStatisticsQuery,
} = auditApi;
