export const ADMIN_TOKEN_STORAGE_KEY = "ebpf-viz:admin-token";

export function getAdminToken(): string | null {
  if (typeof window === "undefined") return null;
  try {
    const token = window.localStorage.getItem(ADMIN_TOKEN_STORAGE_KEY)?.trim();
    return token || null;
  } catch {
    return null;
  }
}

export function setAdminToken(token: string): void {
  if (typeof window === "undefined") return;
  try {
    const trimmed = token.trim();
    if (trimmed) {
      window.localStorage.setItem(ADMIN_TOKEN_STORAGE_KEY, trimmed);
    } else {
      window.localStorage.removeItem(ADMIN_TOKEN_STORAGE_KEY);
    }
  } catch {
    // Ignore localStorage failures, e.g. private browsing or quota errors.
  }
}
