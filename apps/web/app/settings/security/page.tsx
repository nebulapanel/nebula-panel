'use client';

import { FormEvent, useEffect, useMemo, useState } from 'react';
import Image from 'next/image';
import QRCode from 'qrcode';

import { api } from '@/lib/api';

export default function SecuritySettingsPage() {
  const [loading, setLoading] = useState(true);
  const [enabled, setEnabled] = useState(false);
  const [enrollUrl, setEnrollUrl] = useState('');
  const [secret, setSecret] = useState('');
  const [qrDataUrl, setQrDataUrl] = useState('');
  const [code, setCode] = useState('');
  const [disableCode, setDisableCode] = useState('');
  const [error, setError] = useState('');

  const enrolling = !!enrollUrl && !!secret;

  async function refresh() {
    setLoading(true);
    setError('');
    try {
      const st = await api.totpStatus();
      setEnabled(!!st.enabled);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void refresh();
  }, []);

  useEffect(() => {
    if (!enrollUrl) {
      setQrDataUrl('');
      return;
    }
    void (async () => {
      try {
        const url = await QRCode.toDataURL(enrollUrl, { margin: 1, width: 220 });
        setQrDataUrl(url);
      } catch {
        setQrDataUrl('');
      }
    })();
  }, [enrollUrl]);

  const instructions = useMemo(() => {
    if (enabled) {
      return '2FA is enabled. You will be asked for a 6-digit code at login.';
    }
    return '2FA is optional. You can enable Google Authenticator after login.';
  }, [enabled]);

  async function onStartEnroll() {
    setError('');
    setEnrollUrl('');
    setSecret('');
    setQrDataUrl('');
    setCode('');
    try {
      const res = await api.totpEnrollStart();
      setEnrollUrl(res.otpauth_url);
      setSecret(res.secret_base32);
    } catch (err) {
      setError((err as Error).message);
    }
  }

  async function onVerify(e: FormEvent) {
    e.preventDefault();
    setError('');
    try {
      await api.totpEnrollVerify(code);
      setEnrollUrl('');
      setSecret('');
      setQrDataUrl('');
      setCode('');
      await refresh();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  async function onDisable(e: FormEvent) {
    e.preventDefault();
    setError('');
    try {
      await api.totpDisable(disableCode);
      setDisableCode('');
      await refresh();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  return (
    <section className="panel">
      <div className="login-brand">
        <Image src="/nebula-logo.png" alt="Nebula Panel" width={52} height={52} priority />
        <div>
          <h1>Security</h1>
          <p>{instructions}</p>
        </div>
      </div>

      <div className="top-gap">
        <strong>Status:</strong> {loading ? 'Loading...' : enabled ? 'Enabled' : 'Disabled'}
      </div>

      {!enabled && (
        <div className="top-gap">
          <button className="btn btn-primary" type="button" onClick={onStartEnroll} disabled={loading}>
            Enable 2FA (Google Authenticator)
          </button>
        </div>
      )}

      {enrolling && (
        <div className="grid two top-gap">
          <div className="stack">
            <h2>Scan QR</h2>
            {qrDataUrl ? (
              // eslint-disable-next-line @next/next/no-img-element
              <img src={qrDataUrl} alt="TOTP QR Code" style={{ width: 220, height: 220, borderRadius: 12, border: '1px solid var(--line)' }} />
            ) : (
              <p className="muted">QR generation failed. Use the secret below.</p>
            )}
            <div className="token-box">
              <p style={{ marginTop: 0, color: 'var(--muted)' }}>Secret (Base32)</p>
              <code>{secret}</code>
            </div>
          </div>

          <form onSubmit={onVerify} className="stack">
            <h2>Verify</h2>
            <input value={code} onChange={(e) => setCode(e.target.value)} placeholder="6-digit code" inputMode="numeric" />
            <button className="btn btn-secondary" type="submit">
              Verify and Enable
            </button>
          </form>
        </div>
      )}

      {enabled && (
        <form onSubmit={onDisable} className="stack top-gap">
          <h2>Disable 2FA</h2>
          <input value={disableCode} onChange={(e) => setDisableCode(e.target.value)} placeholder="6-digit code" inputMode="numeric" />
          <button className="btn btn-secondary" type="submit">
            Disable
          </button>
        </form>
      )}

      {error && <p className="error">{error}</p>}
    </section>
  );
}

