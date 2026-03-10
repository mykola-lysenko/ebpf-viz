/**
 * Standalone mode: no authentication.
 * This hook is kept as a no-op stub so any component that still
 * imports it compiles without errors.
 */
export function useAuth() {
  return {
    user: null,
    loading: false,
    error: null,
    isAuthenticated: true,
    logout: async () => {},
    refresh: () => {},
  };
}
