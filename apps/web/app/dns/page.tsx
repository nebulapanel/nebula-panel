'use client';

import { FormEvent, useEffect, useState } from 'react';
import Link from 'next/link';

import { api, DNSRecord, DNSZone } from '@/lib/api';
import { useAuth } from '@/components/auth-provider';

function fmt(ts?: string) {
  if (!ts) return '';
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  return d.toLocaleString();
}

export default function DNSPage() {
  const { me, loading } = useAuth();
  const [zones, setZones] = useState<Array<{ zone: string; serial: number; created_at: string }>>([]);
  const [zoneName, setZoneName] = useState('');
  const [selected, setSelected] = useState('');
  const [zone, setZone] = useState<DNSZone | null>(null);
  const [rType, setRType] = useState('A');
  const [rName, setRName] = useState('');
  const [rValue, setRValue] = useState('');
  const [rTTL, setRTTL] = useState('3600');
  const [rPriority, setRPriority] = useState('');
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState('');
  const [error, setError] = useState('');

  async function refreshZones() {
    setError('');
    const res = await api.dnsListZones();
    setZones(res.zones ?? []);
  }

  async function openZone(z: string) {
    setSelected(z);
    setError('');
    const res = await api.dnsGetZone(z);
    setZone(res);
    setRName(res.zone);
  }

  useEffect(() => {
    if (!me) return;
    refreshZones().catch((err) => setError((err as Error).message));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [me?.id]);

  async function onCreateZone(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError('');
    setNotice('');
    try {
      const res = await api.dnsCreateZone(zoneName.trim());
      setNotice(`Zone created. Job: ${res.job?.id}`);
      setZoneName('');
      await refreshZones();
      await openZone(res.zone.zone);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function onAddRecord(e: FormEvent) {
    e.preventDefault();
    if (!zone) return;
    setBusy(true);
    setError('');
    setNotice('');
    try {
      const ttlNum = Number.parseInt(rTTL, 10);
      const priNum = rPriority.trim() ? Number.parseInt(rPriority, 10) : undefined;
      const rec: DNSRecord = {
        id: '',
        type: rType.trim().toUpperCase(),
        name: rName.trim(),
        value: rValue.trim(),
        ttl: Number.isFinite(ttlNum) ? ttlNum : 3600,
        priority: priNum
      };
      const res = await api.dnsReplaceRecords(zone.zone, [...(zone.records ?? []), rec]);
      setNotice(`Record queued. Job: ${res.job?.id}`);
      const fresh = await api.dnsGetZone(zone.zone);
      setZone(fresh);
      setRValue('');
      setRPriority('');
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function onDeleteRecord(id: string) {
    if (!zone) return;
    if (!confirm('Delete this record?')) return;
    setBusy(true);
    setError('');
    setNotice('');
    try {
      const res = await api.dnsDeleteRecord(zone.zone, id);
      setNotice(`Record deleted. Job: ${res.job?.id}`);
      const fresh = await api.dnsGetZone(zone.zone);
      setZone(fresh);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function onDeleteZone() {
    if (!zone) return;
    if (!confirm(`Delete zone ${zone.zone}?`)) return;
    setBusy(true);
    setError('');
    setNotice('');
    try {
      await api.dnsDeleteZone(zone.zone);
      setNotice(`Delete queued. Check Jobs for progress.`);
      setZone(null);
      setSelected('');
      await refreshZones();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  if (!me && !loading) {
    return (
      <section className="panel">
        <h1>DNS</h1>
        <p className="small">
          You are not logged in. <Link href="/login">Go to login</Link>.
        </p>
      </section>
    );
  }

  return (
    <section className="panel">
      <h1>DNS</h1>
      <p className="small">PowerDNS authoritative zones and records.</p>

      <div className="grid two">
        <div className="panel">
          <h2>Create Zone</h2>
          <form onSubmit={onCreateZone} className="stack">
            <input value={zoneName} onChange={(e) => setZoneName(e.target.value)} placeholder="example.com" />
            <button className="btn btn-primary btn-sm" type="submit" disabled={busy || !zoneName.trim()}>
              Create
            </button>
          </form>

          <h2 className="top-gap">Zones</h2>
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Zone</th>
                  <th>Serial</th>
                  <th>Created</th>
                </tr>
              </thead>
              <tbody>
                {zones.map((z) => (
                  <tr key={z.zone} className={selected === z.zone ? 'active-row' : ''} onClick={() => openZone(z.zone)}>
                    <td>{z.zone}</td>
                    <td>{z.serial}</td>
                    <td>{fmt(z.created_at)}</td>
                  </tr>
                ))}
                {zones.length === 0 && (
                  <tr>
                    <td colSpan={3} className="small">
                      No zones yet.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        <div className="panel">
          <div className="row-between">
            <h2>Records</h2>
            {zone ? (
              <button className="btn btn-ghost btn-sm" type="button" onClick={onDeleteZone} disabled={busy}>
                Delete Zone
              </button>
            ) : null}
          </div>

          {zone ? (
            <>
              <p className="small">
                Zone: <strong>{zone.zone}</strong> · Serial {zone.serial}
              </p>

              <div className="table-wrap">
                <table className="table">
                  <thead>
                    <tr>
                      <th>Type</th>
                      <th>Name</th>
                      <th>Value</th>
                      <th>TTL</th>
                      <th />
                    </tr>
                  </thead>
                  <tbody>
                    {(zone.records ?? []).map((r) => (
                      <tr key={r.id}>
                        <td>{r.type}</td>
                        <td>{r.name}</td>
                        <td className="mono">{r.value}</td>
                        <td>{r.ttl}</td>
                        <td>
                          <div className="row-actions">
                            <button className="btn btn-ghost btn-sm" type="button" onClick={() => onDeleteRecord(r.id)} disabled={busy}>
                              Delete
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                    {(zone.records ?? []).length === 0 && (
                      <tr>
                        <td colSpan={5} className="small">
                          No records yet.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>

              <h3 className="top-gap">Add Record</h3>
              <form onSubmit={onAddRecord} className="grid two">
                <select value={rType} onChange={(e) => setRType(e.target.value)}>
                  <option value="A">A</option>
                  <option value="AAAA">AAAA</option>
                  <option value="CNAME">CNAME</option>
                  <option value="MX">MX</option>
                  <option value="TXT">TXT</option>
                  <option value="NS">NS</option>
                </select>
                <input value={rTTL} onChange={(e) => setRTTL(e.target.value)} placeholder="TTL" inputMode="numeric" />
                <input value={rName} onChange={(e) => setRName(e.target.value)} placeholder="Name (FQDN)" />
                <input value={rValue} onChange={(e) => setRValue(e.target.value)} placeholder="Value" />
                {(rType === 'MX') ? (
                  <input value={rPriority} onChange={(e) => setRPriority(e.target.value)} placeholder="Priority (MX only)" inputMode="numeric" />
                ) : (
                  <div />
                )}
                <button className="btn btn-primary btn-sm" type="submit" disabled={busy || !rName.trim() || !rValue.trim()}>
                  Save (Apply)
                </button>
              </form>
            </>
          ) : (
            <p className="small">Select a zone to manage records.</p>
          )}
        </div>
      </div>

      {notice && <p className="notice">{notice}</p>}
      {error && <p className="error">{error}</p>}
    </section>
  );
}
