import axios, { AxiosInstance, AxiosResponse, AxiosError, InternalAxiosRequestConfig } from 'axios';
import type { ApiResponse, ApiError } from '@/types/common';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api/v1';

class ApiService {
  private api: AxiosInstance;
  private isRefreshing = false;
  private refreshSubscribers: ((token: string) => void)[] = [];

  constructor() {
    this.api = axios.create({
      baseURL: API_BASE_URL,
      headers: {
        'Content-Type': 'application/json',
      },
      timeout: 30000,
    });

    this.setupInterceptors();
  }

  private setupInterceptors(): void {
    // Request interceptor
    this.api.interceptors.request.use(
      (config: InternalAxiosRequestConfig) => {
        const token = this.getAccessToken();
        if (token && config.headers) {
          config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
      },
      (error: AxiosError) => {
        return Promise.reject(error);
      }
    );

    // Response interceptor
    this.api.interceptors.response.use(
      (response: AxiosResponse<ApiResponse>) => response,
      async (error: AxiosError<ApiError>) => {
        const originalRequest = error.config as InternalAxiosRequestConfig & { _retry?: boolean };

        // Handle 401 Unauthorized errors
        if (error.response?.status === 401 && originalRequest && !originalRequest._retry) {
          if (this.isRefreshing) {
            // Wait for the token refresh to complete
            return new Promise((resolve) => {
              this.refreshSubscribers.push((token: string) => {
                if (originalRequest.headers) {
                  originalRequest.headers.Authorization = `Bearer ${token}`;
                }
                resolve(this.api(originalRequest));
              });
            });
          }

          originalRequest._retry = true;
          this.isRefreshing = true;

          try {
            const refreshToken = this.getRefreshToken();
            if (!refreshToken) {
              this.handleAuthFailure();
              return Promise.reject(error);
            }

            const response = await this.api.post<ApiResponse<{ access: string; refresh: string }>>(
              '/auth/refresh',
              { refresh: refreshToken }
            );

            const { access, refresh } = response.data.data;
            this.setTokens(access, refresh);
            this.isRefreshing = false;

            // Notify all subscribers
            this.refreshSubscribers.forEach((callback) => callback(access));
            this.refreshSubscribers = [];

            // Retry original request
            if (originalRequest.headers) {
              originalRequest.headers.Authorization = `Bearer ${access}`;
            }
            return this.api(originalRequest);
          } catch (refreshError) {
            this.isRefreshing = false;
            this.refreshSubscribers = [];
            this.handleAuthFailure();
            return Promise.reject(refreshError);
          }
        }

        return Promise.reject(error);
      }
    );
  }

  // Token management
  private getAccessToken(): string | null {
    return localStorage.getItem('access_token');
  }

  private getRefreshToken(): string | null {
    return localStorage.getItem('refresh_token');
  }

  private setTokens(accessToken: string, refreshToken: string): void {
    localStorage.setItem('access_token', accessToken);
    localStorage.setItem('refresh_token', refreshToken);
  }

  public clearTokens(): void {
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    localStorage.removeItem('user');
  }

  private handleAuthFailure(): void {
    this.clearTokens();
    window.location.href = '/login';
  }

  // HTTP Methods
  public async get<T>(url: string, params?: Record<string, unknown>): Promise<AxiosResponse<ApiResponse<T>>> {
    return this.api.get(url, { params });
  }

  public async post<T>(
    url: string,
    data?: unknown,
    config?: Record<string, unknown>
  ): Promise<AxiosResponse<ApiResponse<T>>> {
    return this.api.post(url, data, config);
  }

  public async put<T>(url: string, data?: unknown): Promise<AxiosResponse<ApiResponse<T>>> {
    return this.api.put(url, data);
  }

  public async patch<T>(url: string, data?: unknown): Promise<AxiosResponse<ApiResponse<T>>> {
    return this.api.patch(url, data);
  }

  public async delete<T>(url: string): Promise<AxiosResponse<ApiResponse<T>>> {
    return this.api.delete(url);
  }

  // File upload
  public async uploadFile<T>(
    url: string,
    file: File,
    additionalData?: Record<string, unknown>,
    onUploadProgress?: (progressEvent: unknown) => void
  ): Promise<AxiosResponse<ApiResponse<T>>> {
    const formData = new FormData();
    formData.append('file', file);

    if (additionalData) {
      Object.entries(additionalData).forEach(([key, value]) => {
        formData.append(key, String(value));
      });
    }

    return this.api.post(url, formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
      onUploadProgress,
    });
  }

  // Multiple file upload
  public async uploadFiles<T>(
    url: string,
    files: File[],
    additionalData?: Record<string, unknown>,
    onUploadProgress?: (progressEvent: unknown) => void
  ): Promise<AxiosResponse<ApiResponse<T>>> {
    const formData = new FormData();

    files.forEach((file, index) => {
      formData.append(`file_${index}`, file);
    });

    if (additionalData) {
      Object.entries(additionalData).forEach(([key, value]) => {
        formData.append(key, String(value));
      });
    }

    return this.api.post(url, formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
      onUploadProgress,
    });
  }

  // Get raw axios instance for custom requests
  public getAxiosInstance(): AxiosInstance {
    return this.api;
  }
}

export const apiService = new ApiService();
export default apiService;
