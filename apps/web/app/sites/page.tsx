'use client';

import { FormEvent, useEffect, useState } from 'react';
import Link from 'next/link';

import { api, Site } from '@/lib/api';
import { useAuth } from '@/components/auth-provider';

function fmt(ts?: string) {
  if (!ts) return '';
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  return d.toLocaleString();
}

export default function SitesPage() {
  const { me, loading } = useAuth();
  const [sites, setSites] = useState<Site[]>([]);
  const [name, setName] = useState('My Site');
  const [domain, setDomain] = useState('');
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState('');
  const [error, setError] = useState('');

  async function refresh() {
    setError('');
    const res = await api.listSites();
    setSites(res.sites ?? []);
  }

  useEffect(() => {
    if (!me) return;
    refresh().catch((err) => setError((err as Error).message));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [me?.id]);

  async function onCreate(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError('');
    setNotice('');
    try {
      const res = await api.createSite(name.trim(), domain.trim());
      setNotice(`Site queued. Job: ${res.job?.id}`);
      setDomain('');
      await refresh();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function onDelete(id: string) {
    if (!confirm('Delete this site? This will remove the Nginx vhost and site directory.')) return;
    setBusy(true);
    setError('');
    setNotice('');
    try {
      const res = await api.deleteSite(id);
      setNotice(`Delete queued. Job: ${res.job?.id}`);
      await refresh();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  if (!me && !loading) {
    return (
      <section className="panel">
        <h1>Sites</h1>
        <p className="small">
          You are not logged in. <Link href="/login">Go to login</Link>.
        </p>
      </section>
    );
  }

  return (
    <section className="panel">
      <h1>Sites</h1>
      <p className="small">Provision Nginx + PHP-FPM sites with optional SSL and databases.</p>

      <div className="grid two">
        <div className="panel">
          <h2>Create Site</h2>
          <form onSubmit={onCreate} className="stack">
            <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Site name" />
            <input value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="example.com" />
            <button className="btn btn-primary" type="submit" disabled={busy || !domain.trim()}>
              Create
            </button>
          </form>
        </div>

        <div className="panel">
          <h2>Installed Sites</h2>
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Domain</th>
                  <th>Name</th>
                  <th>Created</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {sites.map((s) => (
                  <tr key={s.id}>
                    <td>
                      <a href={`http://${s.domain}`} target="_blank" rel="noreferrer">
                        {s.domain}
                      </a>
                    </td>
                    <td>{s.name}</td>
                    <td>{fmt(s.created_at)}</td>
                    <td>
                      <div className="row-actions">
                        <Link className="btn btn-ghost btn-sm" href={`/sites/${encodeURIComponent(s.id)}`}>
                          Manage
                        </Link>
                        <button className="btn btn-ghost btn-sm" type="button" onClick={() => onDelete(s.id)} disabled={busy}>
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
                {sites.length === 0 && (
                  <tr>
                    <td colSpan={4} className="small">
                      No sites yet.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {notice && <p className="notice">{notice}</p>}
      {error && <p className="error">{error}</p>}
    </section>
  );
}
