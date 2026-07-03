import { create } from 'zustand';

export const useScanStore = create((set) => ({
  activeScans: {},
  setScanProgress: (scanId, data) =>
    set((state) => ({ activeScans: { ...state.activeScans, [scanId]: data } })),
  clearScan: (scanId) =>
    set((state) => {
      const next = { ...state.activeScans };
      delete next[scanId];
      return { activeScans: next };
    }),
}));