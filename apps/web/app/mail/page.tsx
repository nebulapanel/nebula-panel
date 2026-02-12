'use client';

import { FormEvent, useEffect, useState } from 'react';
import Link from 'next/link';

import { api, MailAlias, Mailbox, MailDomain } from '@/lib/api';
import { useAuth } from '@/components/auth-provider';

function fmt(ts?: string) {
  if (!ts) return '';
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  return d.toLocaleString();
}

export default function MailPage() {
  const { me, loading } = useAuth();

  const [domains, setDomains] = useState<MailDomain[]>([]);
  const [newDomain, setNewDomain] = useState('');

  const [selectedDomain, setSelectedDomain] = useState('');
  const [mailboxes, setMailboxes] = useState<Mailbox[]>([]);
  const [aliases, setAliases] = useState<MailAlias[]>([]);
  const [dnsAuth, setDNSAuth] = useState<Array<{ type: string; name: string; value: string }>>([]);

  const [mbLocal, setMbLocal] = useState('');
  const [mbPassword, setMbPassword] = useState('');
  const [mbQuota, setMbQuota] = useState('2048');
  const [mbGenerated, setMbGenerated] = useState('');

  const [aliasSource, setAliasSource] = useState('');
  const [aliasDest, setAliasDest] = useState('');

  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState('');
  const [error, setError] = useState('');

  async function refreshDomains() {
    const res = await api.mailListDomains();
    setDomains(res.domains ?? []);
  }

  async function openDomain(domain: string) {
    setSelectedDomain(domain);
    setMbGenerated('');
    const [m, a, d] = await Promise.all([
      api.mailListMailboxes(domain),
      api.mailListAliases(domain),
      api.mailDNSAuth(domain)
    ]);
    setMailboxes(m.mailboxes ?? []);
    setAliases(a.aliases ?? []);
    setDNSAuth(d.records ?? []);
  }

  useEffect(() => {
    if (!me) return;
    refreshDomains().catch((err) => setError((err as Error).message));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [me?.id]);

  async function onCreateDomain(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError('');
    setNotice('');
    try {
      const res = await api.mailCreateDomain(newDomain.trim());
      setNotice(`Mail domain queued. Job: ${res.job?.id}`);
      setNewDomain('');
      await refreshDomains();
      await openDomain(res.domain.domain);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function onCreateMailbox(e: FormEvent) {
    e.preventDefault();
    if (!selectedDomain) return;
    setBusy(true);
    setError('');
    setNotice('');
    setMbGenerated('');
    try {
      const quotaNum = Number.parseInt(mbQuota, 10);
      const res = await api.mailCreateMailbox(selectedDomain, mbLocal.trim(), mbPassword.trim(), Number.isFinite(quotaNum) ? quotaNum : 0);
      setNotice(`Mailbox queued. Job: ${res.job?.id}`);
      setMbGenerated(res.generated_password ?? '');
      setMbLocal('');
      setMbPassword('');
      const m = await api.mailListMailboxes(selectedDomain);
      setMailboxes(m.mailboxes ?? []);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function onDeleteMailbox(id: string) {
    if (!confirm('Delete this mailbox?')) return;
    setBusy(true);
    setError('');
    setNotice('');
    try {
      const res = await api.mailDeleteMailbox(id);
      setNotice(`Delete queued. Job: ${res.job?.id}`);
      if (selectedDomain) {
        const m = await api.mailListMailboxes(selectedDomain);
        setMailboxes(m.mailboxes ?? []);
      }
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function onCreateAlias(e: FormEvent) {
    e.preventDefault();
    if (!selectedDomain) return;
    setBusy(true);
    setError('');
    setNotice('');
    try {
      const res = await api.mailCreateAlias(selectedDomain, aliasSource.trim(), aliasDest.trim());
      setNotice(`Alias queued. Job: ${res.job?.id}`);
      setAliasSource('');
      setAliasDest('');
      const a = await api.mailListAliases(selectedDomain);
      setAliases(a.aliases ?? []);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function onDeleteAlias(id: string) {
    if (!confirm('Delete this alias?')) return;
    setBusy(true);
    setError('');
    setNotice('');
    try {
      const res = await api.mailDeleteAlias(id);
      setNotice(`Alias delete queued. Job: ${(res as any).job?.id ?? ''}`);
      const a = await api.mailListAliases(selectedDomain);
      setAliases(a.aliases ?? []);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  if (!me && !loading) {
    return (
      <section className="panel">
        <h1>Mail</h1>
        <p className="small">
          You are not logged in. <Link href="/login">Go to login</Link>.
        </p>
      </section>
    );
  }

  return (
    <section className="panel">
      <h1>Mail</h1>
      <p className="small">Manage domains, mailboxes, aliases, and DNS auth records.</p>

      <div className="grid two">
        <div className="panel">
          <h2>Create Domain</h2>
          <form onSubmit={onCreateDomain} className="stack">
            <input value={newDomain} onChange={(e) => setNewDomain(e.target.value)} placeholder="example.com" />
            <button className="btn btn-primary btn-sm" type="submit" disabled={busy || !newDomain.trim()}>
              Create
            </button>
          </form>

          <h2 className="top-gap">Domains</h2>
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Domain</th>
                  <th>Created</th>
                </tr>
              </thead>
              <tbody>
                {domains.map((d) => (
                  <tr key={d.domain} className={selectedDomain === d.domain ? 'active-row' : ''} onClick={() => openDomain(d.domain)}>
                    <td>{d.domain}</td>
                    <td>{fmt(d.created_at)}</td>
                  </tr>
                ))}
                {domains.length === 0 && (
                  <tr>
                    <td colSpan={2} className="small">
                      No mail domains yet.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        <div className="panel">
          <h2>Domain Details</h2>
          {selectedDomain ? (
            <>
              <p className="small">
                Selected: <strong>{selectedDomain}</strong>
              </p>

              <h3 className="top-gap">Mailboxes</h3>
              <div className="table-wrap">
                <table className="table">
                  <thead>
                    <tr>
                      <th>Address</th>
                      <th>Quota (MB)</th>
                      <th>Created</th>
                      <th />
                    </tr>
                  </thead>
                  <tbody>
                    {mailboxes.map((m) => (
                      <tr key={m.id}>
                        <td className="mono">{m.address}</td>
                        <td>{m.quota_mb}</td>
                        <td>{fmt(m.created_at)}</td>
                        <td>
                          <div className="row-actions">
                            <button className="btn btn-ghost btn-sm" type="button" onClick={() => onDeleteMailbox(m.id)} disabled={busy}>
                              Delete
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                    {mailboxes.length === 0 && (
                      <tr>
                        <td colSpan={4} className="small">
                          No mailboxes.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>

              <form onSubmit={onCreateMailbox} className="grid two top-gap">
                <input value={mbLocal} onChange={(e) => setMbLocal(e.target.value)} placeholder="local part (e.g. admin)" />
                <input value={mbQuota} onChange={(e) => setMbQuota(e.target.value)} placeholder="quota mb" inputMode="numeric" />
                <input value={mbPassword} onChange={(e) => setMbPassword(e.target.value)} placeholder="password (optional)" type="password" />
                <div />
                <button className="btn btn-primary btn-sm" type="submit" disabled={busy || !mbLocal.trim()}>
                  Create Mailbox
                </button>
              </form>
              {mbGenerated ? (
                <p className="small">
                  Generated password (copy now): <code className="inline-code">{mbGenerated}</code>
                </p>
              ) : null}

              <h3 className="top-gap">Aliases</h3>
              <div className="table-wrap">
                <table className="table">
                  <thead>
                    <tr>
                      <th>Source</th>
                      <th>Destination</th>
                      <th />
                    </tr>
                  </thead>
                  <tbody>
                    {aliases.map((a) => (
                      <tr key={a.id}>
                        <td className="mono">{a.source}</td>
                        <td className="mono">{a.destination}</td>
                        <td>
                          <div className="row-actions">
                            <button className="btn btn-ghost btn-sm" type="button" onClick={() => onDeleteAlias(a.id)} disabled={busy}>
                              Delete
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                    {aliases.length === 0 && (
                      <tr>
                        <td colSpan={3} className="small">
                          No aliases.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>

              <form onSubmit={onCreateAlias} className="grid two top-gap">
                <input value={aliasSource} onChange={(e) => setAliasSource(e.target.value)} placeholder="source (e.g. info@example.com)" />
                <input value={aliasDest} onChange={(e) => setAliasDest(e.target.value)} placeholder="destination (e.g. admin@example.com)" />
                <button className="btn btn-primary btn-sm" type="submit" disabled={busy || !aliasSource.trim() || !aliasDest.trim()}>
                  Create Alias
                </button>
              </form>

              <h3 className="top-gap">DNS Auth Records</h3>
              <div className="table-wrap">
                <table className="table">
                  <thead>
                    <tr>
                      <th>Type</th>
                      <th>Name</th>
                      <th>Value</th>
                    </tr>
                  </thead>
                  <tbody>
                    {dnsAuth.map((r, idx) => (
                      <tr key={idx}>
                        <td>{r.type}</td>
                        <td className="mono">{r.name}</td>
                        <td className="mono">{r.value}</td>
                      </tr>
                    ))}
                    {dnsAuth.length === 0 && (
                      <tr>
                        <td colSpan={3} className="small">
                          No suggestions available.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </>
          ) : (
            <p className="small">Select a mail domain.</p>
          )}
        </div>
      </div>

      {notice && <p className="notice">{notice}</p>}
      {error && <p className="error">{error}</p>}
    </section>
  );
}
