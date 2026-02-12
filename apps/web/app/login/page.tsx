'use client';

import { FormEvent, useEffect, useState } from 'react';
import Image from 'next/image';
import { useRouter } from 'next/navigation';
import { api } from '@/lib/api';
import { setCSRF } from '@/lib/auth';
import { useAuth } from '@/components/auth-provider';

export default function LoginPage() {
  const router = useRouter();
  const { me, refresh } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [totpCode, setTotpCode] = useState('');
  const [preauth, setPreauth] = useState('');
  const [error, setError] = useState('');

  useEffect(() => {
    if (me) {
      router.replace('/');
    }
  }, [me, router]);

  async function onLogin(e: FormEvent) {
    e.preventDefault();
    setError('');
    try {
      const res = await api.login(email, password);
      if (res.totp_required) {
        setPreauth(res.preauth_token ?? '');
        return;
      }
      const csrf = res.csrf_token ?? '';
      if (!csrf) {
        throw new Error('Login succeeded but CSRF token is missing.');
      }
      setCSRF(csrf);
      await refresh();
      router.push('/');
    } catch (err) {
      setError((err as Error).message);
    }
  }

  async function onVerifyTotp(e: FormEvent) {
    e.preventDefault();
    setError('');
    try {
      const res = await api.verifyTotp(preauth, totpCode);
      const csrf = res.csrf_token ?? '';
      if (!csrf) {
        throw new Error('TOTP verify succeeded but CSRF token is missing.');
      }
      setCSRF(csrf);
      await refresh();
      router.push('/');
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
          <p>Enter a 2FA code only if you enabled Google Authenticator.</p>
        </div>
      </div>
      <form onSubmit={onLogin} className="stack">
        <input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="Email" />
        <input value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Password" type="password" />
        <button className="btn btn-primary" type="submit">Login</button>
      </form>

      {preauth && (
        <form onSubmit={onVerifyTotp} className="stack top-gap">
          <input value={totpCode} onChange={(e) => setTotpCode(e.target.value)} placeholder="6-digit code" inputMode="numeric" />
          <button className="btn btn-secondary" type="submit">Verify TOTP</button>
        </form>
      )}

      {error && <p className="error">{error}</p>}
    </section>
  );
}
