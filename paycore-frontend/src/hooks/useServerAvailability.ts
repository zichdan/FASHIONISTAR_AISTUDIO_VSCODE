import { useAppDispatch } from './index';
import { setServerUnavailable } from '@/store/slices/serverStatusSlice';
import { isServerUnavailableError } from '@/utils/errorHandlers';

/**
 * Custom hook to handle server unavailability detection
 * Use this in error handlers to automatically detect and handle server downtime
 */
export const useServerAvailability = () => {
  const dispatch = useAppDispatch();

  /**
   * Check if an error indicates server unavailability and update Redux state
   * @param error - The error object from API calls
   * @returns true if server is unavailable, false otherwise
   */
  const checkServerAvailability = (error: any): boolean => {
    if (isServerUnavailableError(error)) {
      dispatch(setServerUnavailable());
      return true;
    }
    return false;
  };

  return { checkServerAvailability };
};
