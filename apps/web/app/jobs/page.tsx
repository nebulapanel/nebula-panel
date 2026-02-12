'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';

import { api, AuditLog, Job, JobEvent } from '@/lib/api';
import { useAuth } from '@/components/auth-provider';

function fmt(ts?: string) {
  if (!ts) return '';
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  return d.toLocaleString();
}

export default function JobsPage() {
  const { me, loading } = useAuth();
  const [jobs, setJobs] = useState<Job[]>([]);
  const [audit, setAudit] = useState<AuditLog[]>([]);
  const [selected, setSelected] = useState<Job | null>(null);
  const [events, setEvents] = useState<JobEvent[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  async function refresh() {
    setError('');
    const [j, a] = await Promise.all([api.jobsList(80), api.auditLogs()]);
    setJobs(j.jobs ?? []);
    setAudit(a.logs ?? []);
  }

  useEffect(() => {
    if (!me) return;
    refresh().catch((err) => setError((err as Error).message));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [me?.id]);

  async function openJob(job: Job) {
    setSelected(job);
    setBusy(true);
    setError('');
    try {
      const res = await api.jobEvents(job.id);
      setEvents(res.events ?? []);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  if (!me && !loading) {
    return (
      <section className="panel">
        <h1>Jobs & Audit</h1>
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
          <h1>Jobs & Audit</h1>
          <p className="small">Track async tasks and review audit logs.</p>
        </div>
        <button className="btn btn-ghost btn-sm" type="button" onClick={() => refresh()} disabled={busy}>
          Refresh
        </button>
      </div>

      {error && <p className="error">{error}</p>}

      <div className="grid two">
        <div className="panel">
          <h2>Jobs</h2>
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Type</th>
                  <th>Status</th>
                  <th>Target</th>
                  <th>Created</th>
                </tr>
              </thead>
              <tbody>
                {jobs.map((j) => (
                  <tr key={j.id} className={selected?.id === j.id ? 'active-row' : ''} onClick={() => openJob(j)}>
                    <td className="mono">{j.id}</td>
                    <td className="mono">{j.type}</td>
                    <td>
                      <span className={`badge ${j.status === 'done' ? 'ok' : j.status === 'failed' ? 'err' : 'warn'}`}>{j.status}</span>
                    </td>
                    <td className="mono">{j.target_id}</td>
                    <td>{fmt(j.created_at)}</td>
                  </tr>
                ))}
                {jobs.length === 0 && (
                  <tr>
                    <td colSpan={5} className="small">
                      No jobs yet.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        <div className="panel">
          <h2>Job Events</h2>
          {selected ? (
            <>
              <p className="small">
                Job: <span className="mono">{selected.id}</span>
              </p>
              <div className="table-wrap">
                <table className="table">
                  <thead>
                    <tr>
                      <th>Status</th>
                      <th>Message</th>
                      <th>Time</th>
                    </tr>
                  </thead>
                  <tbody>
                    {events.map((e) => (
                      <tr key={e.id}>
                        <td className="mono">{e.status}</td>
                        <td>{e.message ?? ''}</td>
                        <td>{fmt(e.created_at)}</td>
                      </tr>
                    ))}
                    {events.length === 0 && (
                      <tr>
                        <td colSpan={3} className="small">
                          No events.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </>
          ) : (
            <p className="small">Select a job to view events.</p>
          )}
        </div>
      </div>

      <div className="panel">
        <h2>Audit Logs</h2>
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Actor</th>
                <th>Action</th>
                <th>Target</th>
                <th>Summary</th>
              </tr>
            </thead>
            <tbody>
              {audit.map((a) => (
                <tr key={a.id}>
                  <td>{fmt(a.created_at)}</td>
                  <td className="mono">{a.actor_id}</td>
                  <td className="mono">{a.action}</td>
                  <td className="mono">{a.target}</td>
                  <td>{a.summary}</td>
                </tr>
              ))}
              {audit.length === 0 && (
                <tr>
                  <td colSpan={5} className="small">
                    No audit logs.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  );
}
