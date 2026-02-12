'use client';

import { FormEvent, useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import { useParams } from 'next/navigation';

import { api, Database, Site, SSLStatus } from '@/lib/api';
import { useAuth } from '@/components/auth-provider';

function fmt(ts?: string) {
  if (!ts) return '';
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  return d.toLocaleString();
}

export default function SiteDetailPage() {
  const params = useParams<{ id: string }>();
  const siteId = useMemo(() => params?.id ?? '', [params]);
  const { me, loading } = useAuth();

  const [site, setSite] = useState<Site | null>(null);
  const [databases, setDatabases] = useState<Database[]>([]);
  const [ssl, setSSL] = useState<SSLStatus | null>(null);
  const [dbEngine, setDBEngine] = useState<'mariadb' | 'postgres'>('mariadb');
  const [dbName, setDBName] = useState('');
  const [dbUser, setDBUser] = useState('');
  const [generatedPassword, setGeneratedPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState('');
  const [error, setError] = useState('');

  async function refreshAll() {
    setError('');
    const s = await api.getSite(siteId);
    setSite(s);
    const d = await api.listSiteDatabases(siteId);
    setDatabases(d.databases ?? []);
    try {
      const st = await api.sslStatus(siteId);
      setSSL(st);
    } catch {
      setSSL(null);
    }
  }

  useEffect(() => {
    if (!me || !siteId) return;
    refreshAll().catch((err) => setError((err as Error).message));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [me?.id, siteId]);

  async function onCreateDB(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError('');
    setNotice('');
    setGeneratedPassword('');
    try {
      const res = await api.createSiteDatabase(siteId, dbEngine, dbName.trim(), dbUser.trim());
      setGeneratedPassword(res.generated_password ?? '');
      setNotice(`Database queued. Job: ${res.job?.id}`);
      setDBName('');
      setDBUser('');
      const d = await api.listSiteDatabases(siteId);
      setDatabases(d.databases ?? []);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function onDeleteDB(id: string) {
    if (!confirm('Delete this database instance?')) return;
    setBusy(true);
    setError('');
    setNotice('');
    try {
      const res = await api.deleteDatabase(id);
      setNotice(`DB delete queued. Job: ${res.job?.id}`);
      const d = await api.listSiteDatabases(siteId);
      setDatabases(d.databases ?? []);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function onIssueSSL() {
    setBusy(true);
    setError('');
    setNotice('');
    try {
      const res = await api.sslIssue(siteId);
      setNotice(`SSL issuance queued. Job: ${res.job?.id}`);
      const st = await api.sslStatus(siteId);
      setSSL(st);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function onRenewSSL() {
    setBusy(true);
    setError('');
    setNotice('');
    try {
      const res = await api.sslRenew(siteId);
      setNotice(`SSL renewal queued. Job: ${res.job?.id}`);
      const st = await api.sslStatus(siteId);
      setSSL(st);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  if (!me && !loading) {
    return (
      <section className="panel">
        <h1>Site</h1>
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
          <h1>Site</h1>
          {site ? (
            <p className="small">
              <strong>{site.domain}</strong> · {site.name} · Created {fmt(site.created_at)}
              {' · '}
              <a href={`http://${site.domain}`} target="_blank" rel="noreferrer">
                open
              </a>
            </p>
          ) : (
            <p className="small">Loading...</p>
          )}
        </div>
        <Link className="btn btn-ghost btn-sm" href="/sites">
          Back
        </Link>
      </div>

      <div className="grid two">
        <div className="panel">
          <h2>SSL</h2>
          <p className="small">
            Status:{' '}
            <span className={`badge ${ssl?.status === 'active' ? 'ok' : ssl?.status ? 'warn' : ''}`}>
              {ssl?.status ?? 'none'}
            </span>
          </p>
          {ssl?.expires_at ? <p className="small">Expires: {fmt(ssl.expires_at)}</p> : null}
          {ssl?.last_error ? <p className="small">Last error: {ssl.last_error}</p> : null}

          <div className="row-actions">
            <button className="btn btn-primary btn-sm" type="button" onClick={onIssueSSL} disabled={busy}>
              Issue
            </button>
            <button className="btn btn-ghost btn-sm" type="button" onClick={onRenewSSL} disabled={busy}>
              Renew
            </button>
          </div>
        </div>

        <div className="panel">
          <h2>Create Database</h2>
          <form onSubmit={onCreateDB} className="stack">
            <select value={dbEngine} onChange={(e) => setDBEngine(e.target.value as any)}>
              <option value="mariadb">MariaDB</option>
              <option value="postgres">PostgreSQL</option>
            </select>
            <input value={dbName} onChange={(e) => setDBName(e.target.value)} placeholder="db name (letters/numbers/_)" />
            <input value={dbUser} onChange={(e) => setDBUser(e.target.value)} placeholder="db user (optional)" />
            <button className="btn btn-primary btn-sm" type="submit" disabled={busy || !dbName.trim()}>
              Create
            </button>
          </form>
          {generatedPassword ? (
            <p className="small">
              Generated password (copy now): <code className="inline-code">{generatedPassword}</code>
            </p>
          ) : null}
        </div>
      </div>

      <div className="panel">
        <h2>Databases</h2>
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Engine</th>
                <th>Name</th>
                <th>User</th>
                <th>Created</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {databases.map((d) => (
                <tr key={d.id}>
                  <td>{d.engine}</td>
                  <td>{d.name}</td>
                  <td>{d.username}</td>
                  <td>{fmt(d.created_at)}</td>
                  <td>
                    <div className="row-actions">
                      <button className="btn btn-ghost btn-sm" type="button" onClick={() => onDeleteDB(d.id)} disabled={busy}>
                        Delete
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
              {databases.length === 0 && (
                <tr>
                  <td colSpan={5} className="small">
                    No databases yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {notice && <p className="notice">{notice}</p>}
      {error && <p className="error">{error}</p>}
    </section>
  );
}

