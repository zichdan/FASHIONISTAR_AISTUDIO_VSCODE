/**
 * Utility to handle API field validation errors
 * Detects if error is an invalid_entry error with field-level errors
 * and returns them in a format suitable for react-hook-form
 */

export interface FieldErrors {
  [key: string]: string;
}

export interface ApiError {
  status?: string;
  code?: string;
  message?: string;
  data?: FieldErrors | any;
}

/**
 * Check if error has field-level validation errors
 */
export const hasFieldErrors = (error: any): boolean => {
  return (
    error?.data?.code === 'invalid_entry' &&
    error?.data?.data &&
    typeof error.data.data === 'object'
  );
};

/**
 * Extract field errors from API error response
 */
export const getFieldErrors = (error: any): FieldErrors => {
  if (hasFieldErrors(error)) {
    return error.data.data;
  }
  return {};
};

/**
 * Get general error message (for non-field errors)
 */
export const getGeneralErrorMessage = (error: any): string => {
  return error?.data?.message || error?.message || 'An error occurred';
};

/**
 * Set field errors on react-hook-form
 */
export const setFormFieldErrors = (
  setError: any,
  fieldErrors: FieldErrors
): void => {
  Object.entries(fieldErrors).forEach(([field, message]) => {
    setError(field, {
      type: 'server',
      message: message,
    });
  });
};

/**
 * Handle API error and display either field errors or toast message
 * Returns true if field errors were set, false if general error
 */
export const handleApiError = (
  error: any,
  setError: any,
  toast: any
): boolean => {
  if (hasFieldErrors(error)) {
    const fieldErrors = getFieldErrors(error);
    setFormFieldErrors(setError, fieldErrors);

    // Show general toast for field errors
    toast({
      title: 'Validation Error',
      description: 'Please check the form for errors',
      status: 'error',
      duration: 4000,
    });

    return true;
  } else {
    // Show general error toast
    toast({
      title: 'Error',
      description: getGeneralErrorMessage(error),
      status: 'error',
      duration: 5000,
    });

    return false;
  }
};
