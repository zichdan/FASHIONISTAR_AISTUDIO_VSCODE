/**
 * Checks if an error is a KYC required error
 * @param error - The error object from RTK Query
 * @returns True if the error is a KYC required error
 */
export const isKYCRequiredError = (error: any): boolean => {
  return error?.data?.code === 'kyc_required';
};

/**
 * Formats API error messages, with special handling for validation errors
 * @param error - The error object from RTK Query
 * @returns A formatted error message string
 */
export const getErrorMessage = (error: any): string => {
  let errorMessage = error.data?.message || error.message || 'An error occurred';

  // Handle field-level validation errors for invalid_entry
  if (error.data?.code === 'invalid_entry' && error.data?.data) {
    const fieldErrors = Object.entries(error.data.data)
      .map(([field, message]) => {
        // If the message is already descriptive (contains spaces or is a sentence), just return it
        const msgStr = String(message);
        if (msgStr.includes(' ') || msgStr.length > 30 || msgStr.match(/^[A-Z]/)) {
          return msgStr;
        }
        // Otherwise, include the field name for context
        return `${field}: ${msgStr}`;
      })
      .join(', ');
    errorMessage = fieldErrors || errorMessage;
  }

  // Handle KYC required errors
  if (error.data?.code === 'kyc_required') {
    errorMessage = error.data?.message || 'Please complete your KYC verification to continue';
  }

  // Handle insufficient balance errors
  if (error.data?.code === 'insufficient_balance') {
    errorMessage = error.data?.message || 'Insufficient balance for this transaction';
  }

  // Handle authentication errors
  if (error.status === 401) {
    errorMessage = 'Session expired. Please log in again';
  }

  // Handle forbidden errors
  if (error.status === 403) {
    errorMessage = 'You do not have permission to perform this action';
  }

  // Handle not found errors
  if (error.status === 404) {
    errorMessage = error.data?.message || 'Resource not found';
  }

  // Handle server errors
  if (error.status >= 500) {
    errorMessage = 'Server error. Please try again later';
  }

  return errorMessage;
};

/**
 * Checks if an error is an insufficient balance error
 * @param error - The error object from RTK Query
 * @returns True if the error is an insufficient balance error
 */
export const isInsufficientBalanceError = (error: any): boolean => {
  return error?.data?.code === 'insufficient_balance';
};

/**
 * Checks if an error is a validation error
 * @param error - The error object from RTK Query
 * @returns True if the error is a validation error
 */
export const isValidationError = (error: any): boolean => {
  return error?.data?.code === 'invalid_entry';
};

/**
 * Checks if the server is unavailable or unreachable
 * @param error - The error object from RTK Query or Axios
 * @returns True if the server is unavailable
 */
export const isServerUnavailableError = (error: any): boolean => {
  // Check for network errors (server unreachable)
  if (error?.message === 'Network Error' || error?.code === 'ERR_NETWORK') {
    return true;
  }

  // Check for fetch failed errors (common when server is down)
  if (error?.message?.includes('Failed to fetch') || error?.message?.includes('fetch failed')) {
    return true;
  }

  // Check for specific server error status codes
  if (error?.status === 503 || error?.status === 502 || error?.status === 504) {
    return true;
  }

  // Check for ECONNREFUSED or similar connection errors
  if (error?.code === 'ECONNREFUSED' || error?.code === 'ENOTFOUND') {
    return true;
  }

  return false;
};
