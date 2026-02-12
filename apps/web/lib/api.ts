const API_URL = process.env.NEXT_PUBLIC_NEBULA_API_URL ?? '/v1';

import { clearCSRF, getCSRF } from '@/lib/auth';

export type Role = 'admin' | 'user';

export type User = {
  id: string;
  email: string;
  role: Role;
  linux_username: string;
  sftp_enabled: boolean;
  created_at: string;
};

export type Site = {
  id: string;
  name: string;
  domain: string;
  owner_id: string;
  root_path: string;
  created_at: string;
};

export type Database = {
  id: string;
  site_id: string;
  engine: string;
  name: string;
  username: string;
  created_at: string;
};

export type SSLStatus = {
  site_id: string;
  provider: string;
  status: string;
  expires_at: string;
  last_error?: string;
  updated_at: string;
  certificate?: string;
};

export type DNSRecord = {
  id: string;
  type: string;
  name: string;
  value: string;
  ttl: number;
  priority?: number;
};

export type DNSZone = {
  zone: string;
  serial: number;
  created_at: string;
  records: DNSRecord[];
};

export type MailDomain = {
  domain: string;
  created_at: string;
};

export type Mailbox = {
  id: string;
  domain: string;
  address: string;
  quota_mb: number;
  created_at: string;
};

export type MailAlias = {
  id: string;
  domain: string;
  source: string;
  destination: string;
  created_at: string;
};

export type Job = {
  id: string;
  type: string;
  status: string;
  target_id: string;
  message?: string;
  created_at: string;
  finished_at?: string;
};

export type JobEvent = {
  id: string;
  job_id: string;
  status: string;
  message?: string;
  created_at: string;
};

export type AuditLog = {
  id: string;
  actor_id: string;
  action: string;
  target: string;
  summary: string;
  created_at: string;
};

export type VersionInfo = {
  version: string;
  git_sha: string;
  build_time: string;
};

export type FileEntry = {
  name: string;
  is_dir: boolean;
  size: number;
  mod_time: string;
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

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const method = (init?.method ?? 'GET').toUpperCase();
  const headers = new Headers(init?.headers);

  const body = init?.body as unknown;
  const isFormData = typeof FormData !== 'undefined' && body instanceof FormData;
  if (!headers.has('Content-Type') && !isFormData) {
    headers.set('Content-Type', 'application/json');
  }

  const csrfToken = getCSRF();
  if (csrfToken && !isSafeMethod(method) && !headers.has('X-CSRF-Token')) {
    headers.set('X-CSRF-Token', csrfToken);
  }

  const res = await fetch(`${API_URL}${path}`, {
    ...init,
    headers,
    credentials: 'include',
    cache: 'no-store'
  });
  if (!res.ok) {
    if (res.status === 401) {
      clearCSRF();
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
  me: () => request<User>('/auth/me'),

  login: (email: string, password: string) =>
    request<{ totp_required?: boolean; preauth_token?: string; csrf_token?: string }>('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password })
    }),

  verifyTotp: (preauthToken: string, code: string) =>
    request<{ csrf_token?: string }>('/auth/totp/verify', {
      method: 'POST',
      body: JSON.stringify({ preauth_token: preauthToken, code })
    }),

  logout: () =>
    request('/auth/logout', {
      method: 'POST',
      body: JSON.stringify({})
    }),

  totpStatus: () => request<{ enabled: boolean }>('/auth/totp/status'),
  totpEnrollStart: () => request<{ otpauth_url: string; secret_base32: string }>('/auth/totp/enroll/start', { method: 'POST', body: JSON.stringify({}) }),
  totpEnrollVerify: (code: string) => request<{ enabled: boolean }>('/auth/totp/enroll/verify', { method: 'POST', body: JSON.stringify({ code }) }),
  totpDisable: (code: string) => request<{ enabled: boolean }>('/auth/totp/disable', { method: 'POST', body: JSON.stringify({ code }) }),

  listUsers: () => request<{ users: User[] }>('/users'),
  createUser: (email: string, password: string, role: Role) =>
    request<{ user: User; job: Job; sftp_password_once: string }>('/users', { method: 'POST', body: JSON.stringify({ email, password, role }) }),
  rotateSftpPassword: (id: string) =>
    request<{ user: User; job: Job; sftp_password_once: string }>(`/users/${encodeURIComponent(id)}/sftp/rotate-password`, { method: 'POST', body: JSON.stringify({}) }),
  deleteUser: (id: string) => request(`/users/${encodeURIComponent(id)}`, { method: 'DELETE' }),

  listSites: () => request<{ sites: Site[] }>('/sites'),
  getSite: (id: string) => request<Site>(`/sites/${encodeURIComponent(id)}`),
  createSite: (name: string, domain: string, ownerId?: string) =>
    request<{ site: Site; job: Job }>('/sites', { method: 'POST', body: JSON.stringify({ name, domain, owner_id: ownerId }) }),
  deleteSite: (id: string) => request<{ job: Job }>(`/sites/${encodeURIComponent(id)}`, { method: 'DELETE' }),

  listSiteDatabases: (siteId: string) => request<{ databases: Database[] }>(`/sites/${encodeURIComponent(siteId)}/databases`),
  createSiteDatabase: (siteId: string, engine: string, name: string, username: string) =>
    request<{ database: Database; job: Job; generated_password: string }>(`/sites/${encodeURIComponent(siteId)}/databases`, {
      method: 'POST',
      body: JSON.stringify({ engine, name, username })
    }),
  deleteDatabase: (dbId: string) => request<{ job: Job }>(`/databases/${encodeURIComponent(dbId)}`, { method: 'DELETE' }),

  sslIssue: (siteId: string) => request<{ job: Job }>(`/sites/${encodeURIComponent(siteId)}/ssl/issue`, { method: 'POST', body: JSON.stringify({}) }),
  sslRenew: (siteId: string) => request<{ job: Job }>(`/sites/${encodeURIComponent(siteId)}/ssl/renew`, { method: 'POST', body: JSON.stringify({}) }),
  sslStatus: (siteId: string) => request<SSLStatus>(`/sites/${encodeURIComponent(siteId)}/ssl/status`),

  dnsListZones: () => request<{ zones: Array<{ zone: string; serial: number; created_at: string }> }>('/dns/zones'),
  dnsCreateZone: (zone: string) => request<{ zone: DNSZone; job: Job }>('/dns/zones', { method: 'POST', body: JSON.stringify({ zone }) }),
  dnsGetZone: (zone: string) => request<DNSZone>(`/dns/zones/${encodeURIComponent(zone)}`),
  dnsReplaceRecords: (zone: string, records: DNSRecord[]) =>
    request<{ zone: DNSZone; job: Job }>(`/dns/zones/${encodeURIComponent(zone)}/records`, { method: 'PUT', body: JSON.stringify({ records }) }),
  dnsDeleteRecord: (zone: string, recordId: string) =>
    request<{ zone: DNSZone; job: Job }>(`/dns/zones/${encodeURIComponent(zone)}/records/${encodeURIComponent(recordId)}`, { method: 'DELETE' }),
  dnsDeleteZone: (zone: string) => request('/dns/zones/' + encodeURIComponent(zone), { method: 'DELETE' }),

  mailListDomains: () => request<{ domains: MailDomain[] }>('/mail/domains'),
  mailCreateDomain: (domain: string) => request<{ domain: MailDomain; job: Job }>('/mail/domains', { method: 'POST', body: JSON.stringify({ domain }) }),
  mailListMailboxes: (domain: string) => request<{ mailboxes: Mailbox[] }>(`/mail/domains/${encodeURIComponent(domain)}/mailboxes`),
  mailCreateMailbox: (domain: string, localPart: string, password?: string, quotaMB?: number) =>
    request<{ mailbox: Mailbox; job: Job; generated_password: string }>(`/mail/domains/${encodeURIComponent(domain)}/mailboxes`, {
      method: 'POST',
      body: JSON.stringify({ local_part: localPart, password: password ?? '', quota_mb: quotaMB ?? 0 })
    }),
  mailDeleteMailbox: (mailboxId: string) => request<{ job: Job }>(`/mail/mailboxes/${encodeURIComponent(mailboxId)}`, { method: 'DELETE' }),
  mailListAliases: (domain?: string) => request<{ aliases: MailAlias[] }>(`/mail/aliases${domain ? `?domain=${encodeURIComponent(domain)}` : ''}`),
  mailCreateAlias: (domain: string, source: string, destination: string) =>
    request<{ alias: MailAlias; job: Job }>('/mail/aliases', { method: 'POST', body: JSON.stringify({ domain, source, destination }) }),
  mailDeleteAlias: (aliasId: string) => request('/mail/aliases/' + encodeURIComponent(aliasId), { method: 'DELETE' }),
  mailDNSAuth: (domain: string) => request<{ records: Array<{ type: string; name: string; value: string }> }>(`/mail/domains/${encodeURIComponent(domain)}/dns-auth`),

  filesTree: (path: string) => request<{ path: string; entries: FileEntry[] }>(`/files/tree?path=${encodeURIComponent(path)}`),
  filesMkdir: (path: string) => request<{ path: string }>('/files/mkdir', { method: 'POST', body: JSON.stringify({ path }) }),
  filesDelete: (path: string) => request('/files', { method: 'DELETE', body: JSON.stringify({ path }) }),
  filesUpload: (path: string, contentBase64: string) =>
    request<{ path: string; bytes: number }>('/files/upload', { method: 'POST', body: JSON.stringify({ path, content_base64: contentBase64 }) }),

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
    }),

  backupsList: () => request<{ backups: Array<{ id: string; scope: string; status: string; bucket_path: string; created_at: string }> }>('/backups'),
  backupsRun: (scope: string) => request<{ backup: any; job: Job }>('/backups/run', { method: 'POST', body: JSON.stringify({ scope }) }),
  backupsRestore: (id: string) => request<{ job: Job }>(`/backups/${encodeURIComponent(id)}/restore`, { method: 'POST', body: JSON.stringify({}) }),
  backupGet: (id: string) => request<any>(`/backups/${encodeURIComponent(id)}`),

  jobsList: (limit = 50) => request<{ jobs: Job[] }>(`/jobs?limit=${encodeURIComponent(String(limit))}`),
  jobGet: (id: string) => request<Job>(`/jobs/${encodeURIComponent(id)}`),
  jobEvents: (id: string) => request<{ events: JobEvent[] }>(`/jobs/${encodeURIComponent(id)}/events`),
  auditLogs: () => request<{ logs: AuditLog[] }>('/audit-logs'),

  version: () => request<VersionInfo>('/version')
};
