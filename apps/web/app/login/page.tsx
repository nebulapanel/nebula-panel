'use client';

import { FormEvent, useState } from 'react';
import Image from 'next/image';
import { api } from '@/lib/api';

export default function LoginPage() {
  const [email, setEmail] = useState('admin@localhost');
  const [password, setPassword] = useState('admin123!');
  const [totpCode, setTotpCode] = useState('000000');
  const [preauth, setPreauth] = useState('');
  const [sessionToken, setSessionToken] = useState('');
  const [csrfToken, setCsrfToken] = useState('');
  const [error, setError] = useState('');

  async function onLogin(e: FormEvent) {
    e.preventDefault();
    setError('');
    try {
      const res = await api.login(email, password);
      setCsrfToken(res.csrf_token ?? '');
      if (res.totp_required) {
        setPreauth(res.preauth_token ?? '');
        return;
      }
      setSessionToken(res.session?.token ?? '');
    } catch (err) {
      setError((err as Error).message);
    }
  }

  async function onVerifyTotp(e: FormEvent) {
    e.preventDefault();
    setError('');
    try {
      const res = await api.verifyTotp(preauth, totpCode);
      setSessionToken(res.session?.token ?? '');
      setCsrfToken(res.csrf_token ?? csrfToken);
    } catch (err) {
      setError((err as Error).message);
    }
  }

  return (
    <section className="panel narrow">
      <div className="login-brand">
        <Image src="/nebula-logo.png" alt="Nebula Panel" width={72} height={72} priority />
        <div>
          <h1>Admin Login</h1>
          <p>Use TOTP after password for admin sessions.</p>
        </div>
      </div>
      <form onSubmit={onLogin} className="stack">
        <input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="Email" />
        <input value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Password" type="password" />
        <button className="btn btn-primary" type="submit">Login</button>
      </form>

      {preauth && (
        <form onSubmit={onVerifyTotp} className="stack top-gap">
          <input value={totpCode} onChange={(e) => setTotpCode(e.target.value)} placeholder="TOTP code" />
          <button className="btn btn-secondary" type="submit">Verify TOTP</button>
        </form>
      )}

      {sessionToken && (
        <div className="token-box">
          <p>Session Token</p>
          <code>{sessionToken}</code>
          <p>CSRF Token</p>
          <code>{csrfToken}</code>
        </div>
      )}

      {error && <p className="error">{error}</p>}
    </section>
  );
}
