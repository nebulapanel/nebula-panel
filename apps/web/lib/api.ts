const API_URL = process.env.NEXT_PUBLIC_NEBULA_API_URL ?? '/v1';

import { clearAuth, getAuth } from '@/lib/auth';

type RequestInitWithAuth = RequestInit & {
  auth?: { sessionToken?: string; csrfToken?: string } | null;
};

function isSafeMethod(method: string) {
  switch (method.toUpperCase()) {
    case 'GET':
    case 'HEAD':
    case 'OPTIONS':
      return true;
    default:
      return false;
  }
}

async function request<T>(path: string, init?: RequestInitWithAuth): Promise<T> {
  const method = (init?.method ?? 'GET').toUpperCase();
  const headers = new Headers(init?.headers);

  if (!headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }

  const auth = init?.auth ?? getAuth();
  if (auth?.sessionToken && !headers.has('Authorization')) {
    headers.set('Authorization', `Bearer ${auth.sessionToken}`);
  }
  if (auth?.csrfToken && !isSafeMethod(method) && !headers.has('X-CSRF-Token')) {
    headers.set('X-CSRF-Token', auth.csrfToken);
  }

  const res = await fetch(`${API_URL}${path}`, {
    ...init,
    headers,
    credentials: 'include',
    cache: 'no-store'
  });
  if (!res.ok) {
    if (res.status === 401) {
      clearAuth();
    }
    const txt = await res.text();
    throw new Error(`API ${res.status}: ${txt}`);
  }
  if (res.status === 204) {
    return {} as T;
  }
  return res.json() as Promise<T>;
}

export const api = {
  login: (email: string, password: string) =>
    request<{ totp_required?: boolean; preauth_token?: string; csrf_token?: string; session?: { token: string } }>('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password })
    }),

  verifyTotp: (preauthToken: string, code: string) =>
    request<{ session?: { token: string }; csrf_token?: string }>('/auth/totp/verify', {
      method: 'POST',
      body: JSON.stringify({ preauth_token: preauthToken, code })
    }),

  logout: () =>
    request('/auth/logout', {
      method: 'POST',
      body: JSON.stringify({ session_token: getAuth()?.sessionToken ?? '' })
    }),

  createWebmailSession: (mailbox: string, password: string) =>
    request<{ token: string }>('/webmail/session', {
      method: 'POST',
      body: JSON.stringify({ mailbox, password })
    }),

  getWebmailMessages: (webmailToken: string, folder: string) =>
    request<{ messages: Array<{ id: string; subject: string; from: string }> }>(`/webmail/messages?folder=${encodeURIComponent(folder)}`, {
      method: 'GET',
      headers: {
        'X-Webmail-Token': webmailToken
      }
    }),

  sendWebmailMessage: (webmailToken: string, to: string, subject: string, body: string) =>
    request('/webmail/messages/send', {
      method: 'POST',
      headers: {
        'X-Webmail-Token': webmailToken
      },
      body: JSON.stringify({ to, subject, body })
    })
};
