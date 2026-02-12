'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';

import { api, Site, SSLStatus } from '@/lib/api';
import { useAuth } from '@/components/auth-provider';

function fmt(ts?: string) {
  if (!ts) return '';
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  return d.toLocaleString();
}

export default function SSLPage() {
  const { me, loading } = useAuth();
  const [sites, setSites] = useState<Site[]>([]);
  const [statusBySite, setStatusBySite] = useState<Record<string, SSLStatus | null>>({});
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState('');
  const [error, setError] = useState('');

  async function refreshSites() {
    const res = await api.listSites();
    setSites(res.sites ?? []);
  }

  async function refreshStatuses() {
    const next: Record<string, SSLStatus | null> = {};
    await Promise.all(
      sites.map(async (s) => {
        try {
          next[s.id] = await api.sslStatus(s.id);
        } catch {
          next[s.id] = null;
        }
      })
    );
    setStatusBySite(next);
  }

  useEffect(() => {
    if (!me) return;
    refreshSites()
      .catch((err) => setError((err as Error).message))
      .finally(() => {});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [me?.id]);

  useEffect(() => {
    if (!me) return;
    if (sites.length === 0) return;
    refreshStatuses().catch(() => {});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sites.map((s) => s.id).join('|')]);

  async function issue(siteId: string) {
    setBusy(true);
    setError('');
    setNotice('');
    try {
      const res = await api.sslIssue(siteId);
      setNotice(`SSL queued. Job: ${res.job?.id}`);
      await refreshStatuses();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function renew(siteId: string) {
    setBusy(true);
    setError('');
    setNotice('');
    try {
      const res = await api.sslRenew(siteId);
      setNotice(`Renewal queued. Job: ${res.job?.id}`);
      await refreshStatuses();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  if (!me && !loading) {
    return (
      <section className="panel">
        <h1>SSL</h1>
        <p className="small">
          You are not logged in. <Link href="/login">Go to login</Link>.
        </p>
      </section>
    );
  }

  return (
    <section className="panel">
      <div className="row-between">
        <div>
          <h1>SSL</h1>
          <p className="small">Issue and renew certificates with Let&apos;s Encrypt primary and ZeroSSL fallback.</p>
        </div>
        <button className="btn btn-ghost btn-sm" type="button" onClick={() => refreshStatuses()} disabled={busy || sites.length === 0}>
          Refresh
        </button>
      </div>

      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>Site</th>
              <th>Status</th>
              <th>Provider</th>
              <th>Expires</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {sites.map((s) => {
              const st = statusBySite[s.id];
              const badge =
                st?.status === 'active' ? 'ok' : st?.status === 'failed' ? 'err' : st?.status ? 'warn' : '';
              return (
                <tr key={s.id}>
                  <td>
                    <Link href={`/sites/${encodeURIComponent(s.id)}`}>{s.domain}</Link>
                  </td>
                  <td>
                    <span className={`badge ${badge}`}>{st?.status ?? 'none'}</span>
                  </td>
                  <td className="mono">{st?.provider ?? '-'}</td>
                  <td>{st?.expires_at ? fmt(st.expires_at) : '-'}</td>
                  <td>
                    <div className="row-actions">
                      <button className="btn btn-primary btn-sm" type="button" onClick={() => issue(s.id)} disabled={busy}>
                        Issue
                      </button>
                      <button className="btn btn-ghost btn-sm" type="button" onClick={() => renew(s.id)} disabled={busy}>
                        Renew
                      </button>
                    </div>
                  </td>
                </tr>
              );
            })}
            {sites.length === 0 && (
              <tr>
                <td colSpan={5} className="small">
                  No sites yet. Create a site first.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {notice && <p className="notice">{notice}</p>}
      {error && <p className="error">{error}</p>}
    </section>
  );
}
