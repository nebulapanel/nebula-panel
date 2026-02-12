'use client';

import { FormEvent, useEffect, useState } from 'react';
import Link from 'next/link';

import { api, Role, User } from '@/lib/api';
import { useAuth } from '@/components/auth-provider';

function fmt(ts?: string) {
  if (!ts) return '';
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  return d.toLocaleString();
}

export default function UsersPage() {
  const { me, loading } = useAuth();
  const [users, setUsers] = useState<User[]>([]);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState<Role>('user');
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState('');
  const [error, setError] = useState('');
  const [sftpPasswordOnce, setSftpPasswordOnce] = useState('');

  async function refresh() {
    setError('');
    const res = await api.listUsers();
    setUsers(res.users ?? []);
  }

  useEffect(() => {
    if (!me) return;
    if (me.role !== 'admin') return;
    refresh().catch((err) => setError((err as Error).message));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [me?.id]);

  async function onCreate(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError('');
    setNotice('');
    setSftpPasswordOnce('');
    try {
      const res = await api.createUser(email.trim(), password, role);
      setNotice(`User created. Job: ${res.job?.id}`);
      setSftpPasswordOnce(res.sftp_password_once ?? '');
      setEmail('');
      setPassword('');
      await refresh();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function onRotateSftp(id: string) {
    setBusy(true);
    setError('');
    setNotice('');
    setSftpPasswordOnce('');
    try {
      const res = await api.rotateSftpPassword(id);
      setNotice(`SFTP password rotated. Job: ${res.job?.id}`);
      setSftpPasswordOnce(res.sftp_password_once ?? '');
      await refresh();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function onDelete(id: string) {
    if (!confirm('Delete this panel user?')) return;
    setBusy(true);
    setError('');
    setNotice('');
    setSftpPasswordOnce('');
    try {
      await api.deleteUser(id);
      setNotice('User deleted.');
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
        <h1>Users</h1>
        <p className="small">
          You are not logged in. <Link href="/login">Go to login</Link>.
        </p>
      </section>
    );
  }

  if (me && me.role !== 'admin') {
    return (
      <section className="panel">
        <h1>Users</h1>
        <p className="small">This page is admin-only.</p>
      </section>
    );
  }

  return (
    <section className="panel">
      <h1>Users</h1>
      <p className="small">Create panel users (Linux user + jailed SFTP is provisioned asynchronously).</p>

      <div className="grid two">
        <div className="panel">
          <h2>Create User</h2>
          <form onSubmit={onCreate} className="stack">
            <input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="user@example.com" />
            <input value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Password" type="password" />
            <select value={role} onChange={(e) => setRole(e.target.value as Role)}>
              <option value="user">User</option>
              <option value="admin">Admin</option>
            </select>
            <button className="btn btn-primary btn-sm" type="submit" disabled={busy || !email.trim() || !password}>
              Create
            </button>
          </form>
          {sftpPasswordOnce ? (
            <p className="small">
              SFTP password (copy now): <code className="inline-code">{sftpPasswordOnce}</code>
            </p>
          ) : null}
        </div>

        <div className="panel">
          <h2>Existing Users</h2>
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Email</th>
                  <th>Role</th>
                  <th>Linux</th>
                  <th>Created</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {users.map((u) => (
                  <tr key={u.id}>
                    <td className="mono">{u.email}</td>
                    <td>{u.role}</td>
                    <td className="mono">{u.linux_username}</td>
                    <td>{fmt(u.created_at)}</td>
                    <td>
                      <div className="row-actions">
                        <button className="btn btn-ghost btn-sm" type="button" onClick={() => onRotateSftp(u.id)} disabled={busy}>
                          Rotate SFTP
                        </button>
                        {u.id === me?.id ? null : (
                          <button className="btn btn-ghost btn-sm" type="button" onClick={() => onDelete(u.id)} disabled={busy}>
                            Delete
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
                {users.length === 0 && (
                  <tr>
                    <td colSpan={5} className="small">
                      No users.
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
