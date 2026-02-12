'use client';

import { FormEvent, useEffect, useMemo, useState } from 'react';
import Link from 'next/link';

import { api, FileEntry } from '@/lib/api';
import { useAuth } from '@/components/auth-provider';

function fmt(ts?: string) {
  if (!ts) return '';
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  return d.toLocaleString();
}

function joinPath(a: string, b: string) {
  const left = a.trim().replace(/\/+$/, '');
  const right = b.trim().replace(/^\/+/, '');
  if (!left) return right;
  if (!right) return left;
  return `${left}/${right}`;
}

function parentPath(p: string) {
  const cleaned = p.trim().replace(/\/+$/, '');
  if (!cleaned) return '';
  const parts = cleaned.split('/');
  parts.pop();
  return parts.join('/');
}

async function fileToBase64(file: File): Promise<string> {
  const buf = await file.arrayBuffer();
  const bytes = new Uint8Array(buf);
  let bin = '';
  for (let i = 0; i < bytes.byteLength; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

export default function FilesPage() {
  const { me, loading } = useAuth();
  const [cwd, setCwd] = useState('');
  const [entries, setEntries] = useState<FileEntry[]>([]);
  const [mkdirName, setMkdirName] = useState('');
  const [uploadFile, setUploadFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState('');
  const [error, setError] = useState('');

  const breadcrumb = useMemo(() => (cwd ? cwd.split('/') : []), [cwd]);

  async function refresh(path = cwd) {
    setError('');
    const res = await api.filesTree(path);
    setEntries((res.entries ?? []).sort((a, b) => Number(b.is_dir) - Number(a.is_dir) || a.name.localeCompare(b.name)));
  }

  useEffect(() => {
    if (!me) return;
    refresh().catch((err) => setError((err as Error).message));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [me?.id]);

  async function onOpenDir(name: string) {
    const next = joinPath(cwd, name);
    setCwd(next);
    await refresh(next);
  }

  async function onUp() {
    const next = parentPath(cwd);
    setCwd(next);
    await refresh(next);
  }

  async function onMkdir(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError('');
    setNotice('');
    try {
      const target = joinPath(cwd, mkdirName);
      await api.filesMkdir(target);
      setNotice('Directory created.');
      setMkdirName('');
      await refresh();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function onUpload(e: FormEvent) {
    e.preventDefault();
    if (!uploadFile) return;
    setBusy(true);
    setError('');
    setNotice('');
    try {
      const dest = joinPath(cwd, uploadFile.name);
      const b64 = await fileToBase64(uploadFile);
      await api.filesUpload(dest, b64);
      setNotice('File uploaded.');
      setUploadFile(null);
      await refresh();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function onDelete(name: string) {
    if (!confirm(`Delete ${name}?`)) return;
    setBusy(true);
    setError('');
    setNotice('');
    try {
      const target = joinPath(cwd, name);
      await api.filesDelete(target);
      setNotice('Deleted.');
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
        <h1>Files</h1>
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
          <h1>Files</h1>
          <p className="small">
            Jailed file operations in the panel storage root for your account.
          </p>
        </div>
        <button className="btn btn-ghost btn-sm" type="button" onClick={() => refresh()} disabled={busy}>
          Refresh
        </button>
      </div>

      <div className="panel">
        <div className="row-between">
          <div className="mono">
            /{breadcrumb.map((b, idx) => (
              <span key={idx}>
                {b}
                {idx < breadcrumb.length - 1 ? '/' : ''}
              </span>
            ))}
          </div>
          <div className="row-actions">
            <button className="btn btn-ghost btn-sm" type="button" onClick={onUp} disabled={busy || !cwd}>
              Up
            </button>
          </div>
        </div>

        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Type</th>
                <th>Size</th>
                <th>Modified</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {entries.map((e) => (
                <tr key={e.name}>
                  <td>
                    {e.is_dir ? (
                      <button className="linkish" type="button" onClick={() => onOpenDir(e.name)} disabled={busy}>
                        {e.name}/
                      </button>
                    ) : (
                      <span className="mono">{e.name}</span>
                    )}
                  </td>
                  <td>{e.is_dir ? 'dir' : 'file'}</td>
                  <td className="mono">{e.is_dir ? '-' : String(e.size)}</td>
                  <td>{fmt(e.mod_time)}</td>
                  <td>
                    <div className="row-actions">
                      <button className="btn btn-ghost btn-sm" type="button" onClick={() => onDelete(e.name)} disabled={busy}>
                        Delete
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
              {entries.length === 0 && (
                <tr>
                  <td colSpan={5} className="small">
                    Empty directory.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      <div className="grid two">
        <div className="panel">
          <h2>Upload</h2>
          <form onSubmit={onUpload} className="stack">
            <input type="file" onChange={(e) => setUploadFile(e.target.files?.[0] ?? null)} />
            <button className="btn btn-primary btn-sm" type="submit" disabled={busy || !uploadFile}>
              Upload
            </button>
            <p className="small">MVP upload uses base64 JSON; keep files small.</p>
          </form>
        </div>

        <div className="panel">
          <h2>Create Folder</h2>
          <form onSubmit={onMkdir} className="stack">
            <input value={mkdirName} onChange={(e) => setMkdirName(e.target.value)} placeholder="folder name" />
            <button className="btn btn-primary btn-sm" type="submit" disabled={busy || !mkdirName.trim()}>
              Create
            </button>
          </form>
        </div>
      </div>

      {notice && <p className="notice">{notice}</p>}
      {error && <p className="error">{error}</p>}
    </section>
  );
}
