import { createSlice } from '@reduxjs/toolkit';
import type { RootState } from '@/store';

interface ServerStatusState {
  isServerAvailable: boolean;
  lastChecked: number | null;
}

const initialState: ServerStatusState = {
  isServerAvailable: true,
  lastChecked: null,
};

const serverStatusSlice = createSlice({
  name: 'serverStatus',
  initialState,
  reducers: {
    setServerUnavailable: (state) => {
      state.isServerAvailable = false;
      state.lastChecked = Date.now();
    },
    setServerAvailable: (state) => {
      state.isServerAvailable = true;
      state.lastChecked = Date.now();
    },
    resetServerStatus: (state) => {
      state.isServerAvailable = true;
      state.lastChecked = null;
    },
  },
});

export const { setServerUnavailable, setServerAvailable, resetServerStatus } =
  serverStatusSlice.actions;

export const selectIsServerAvailable = (state: RootState) =>
  state.serverStatus.isServerAvailable;
export const selectLastChecked = (state: RootState) => state.serverStatus.lastChecked;

export default serverStatusSlice.reducer;
