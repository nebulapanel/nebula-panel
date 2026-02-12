'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';

import { api } from '@/lib/api';
import { useAuth } from '@/components/auth-provider';

function fmt(ts?: string) {
  if (!ts) return '';
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  return d.toLocaleString();
}

export default function BackupsPage() {
  const { me, loading } = useAuth();
  const [backups, setBackups] = useState<Array<{ id: string; scope: string; status: string; bucket_path: string; created_at: string }>>([]);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState('');
  const [error, setError] = useState('');

  async function refresh() {
    const res = await api.backupsList();
    setBackups(res.backups ?? []);
  }

  useEffect(() => {
    if (!me) return;
    refresh().catch((err) => setError((err as Error).message));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [me?.id]);

  async function runBackup() {
    setBusy(true);
    setError('');
    setNotice('');
    try {
      const res = await api.backupsRun('full');
      setNotice(`Backup queued. Job: ${res.job?.id}`);
      await refresh();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function restoreBackup(id: string) {
    if (!confirm('Restore this backup? (MVP restore pipeline is limited)')) return;
    setBusy(true);
    setError('');
    setNotice('');
    try {
      const res = await api.backupsRestore(id);
      setNotice(`Restore queued. Job: ${res.job?.id}`);
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
        <h1>Backups</h1>
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
          <h1>Backups</h1>
          <p className="small">Nightly encrypted backups to S3-compatible storage with restore operations.</p>
        </div>
        <button className="btn btn-primary btn-sm" type="button" onClick={runBackup} disabled={busy}>
          Run Backup
        </button>
      </div>

      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Scope</th>
              <th>Status</th>
              <th>Destination</th>
              <th>Created</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {backups.map((b) => (
              <tr key={b.id}>
                <td className="mono">{b.id}</td>
                <td>{b.scope}</td>
                <td>
                  <span className={`badge ${b.status === 'done' ? 'ok' : b.status === 'failed' ? 'err' : 'warn'}`}>{b.status}</span>
                </td>
                <td className="mono">{b.bucket_path}</td>
                <td>{fmt(b.created_at)}</td>
                <td>
                  <div className="row-actions">
                    <button className="btn btn-ghost btn-sm" type="button" onClick={() => restoreBackup(b.id)} disabled={busy}>
                      Restore
                    </button>
                  </div>
                </td>
              </tr>
            ))}
            {backups.length === 0 && (
              <tr>
                <td colSpan={6} className="small">
                  No backups yet.
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
