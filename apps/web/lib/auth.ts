const SESSION_KEY = 'nebula_session_token';
const CSRF_KEY = 'nebula_csrf_token';

export type AuthState = {
  sessionToken: string;
  csrfToken: string;
};

export function getAuth(): AuthState | null {
  if (typeof window === 'undefined') return null;
  const sessionToken = window.localStorage.getItem(SESSION_KEY) ?? '';
  const csrfToken = window.localStorage.getItem(CSRF_KEY) ?? '';
  if (!sessionToken || !csrfToken) return null;
  return { sessionToken, csrfToken };
}

export function setAuth(auth: AuthState) {
  if (typeof window === 'undefined') return;
  window.localStorage.setItem(SESSION_KEY, auth.sessionToken);
  window.localStorage.setItem(CSRF_KEY, auth.csrfToken);
}

export function clearAuth() {
  if (typeof window === 'undefined') return;
  window.localStorage.removeItem(SESSION_KEY);
  window.localStorage.removeItem(CSRF_KEY);
}

