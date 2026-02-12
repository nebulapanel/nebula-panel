const CSRF_KEY = 'nebula_csrf_token';

export function getCSRF(): string | null {
  if (typeof window === 'undefined') return null;
  const csrfToken = window.localStorage.getItem(CSRF_KEY) ?? '';
  if (!csrfToken) return null;
  return csrfToken;
}

export function setCSRF(csrfToken: string) {
  if (typeof window === 'undefined') return;
  window.localStorage.setItem(CSRF_KEY, csrfToken);
}

export function clearCSRF() {
  if (typeof window === 'undefined') return;
  window.localStorage.removeItem(CSRF_KEY);
}
