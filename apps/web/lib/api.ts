const API_URL = process.env.NEXT_PUBLIC_NEBULA_API_URL ?? '/v1';

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_URL}${path}`, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...(init?.headers ?? {})
    },
    credentials: 'include',
    cache: 'no-store'
  });
  if (!res.ok) {
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

  createWebmailSession: (sessionToken: string, csrfToken: string, mailbox: string, password: string) =>
    request<{ token: string }>('/webmail/session', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${sessionToken}`,
        'X-CSRF-Token': csrfToken
      },
      body: JSON.stringify({ mailbox, password })
    }),

  getWebmailMessages: (sessionToken: string, webmailToken: string, folder: string) =>
    request<{ messages: Array<{ id: string; subject: string; from: string }> }>(`/webmail/messages?folder=${encodeURIComponent(folder)}`, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${sessionToken}`,
        'X-Webmail-Token': webmailToken
      }
    }),

  sendWebmailMessage: (
    sessionToken: string,
    csrfToken: string,
    webmailToken: string,
    to: string,
    subject: string,
    body: string
  ) =>
    request('/webmail/messages/send', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${sessionToken}`,
        'X-CSRF-Token': csrfToken,
        'X-Webmail-Token': webmailToken
      },
      body: JSON.stringify({ to, subject, body })
    })
};
