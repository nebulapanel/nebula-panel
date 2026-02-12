'use client';

import { FormEvent, useEffect, useState } from 'react';
import Image from 'next/image';
import { useRouter } from 'next/navigation';
import { api } from '@/lib/api';
import { getAuth, setAuth } from '@/lib/auth';

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState('admin@localhost');
  const [password, setPassword] = useState('admin123!');
  const [totpCode, setTotpCode] = useState('000000');
  const [preauth, setPreauth] = useState('');
  const [error, setError] = useState('');

  useEffect(() => {
    if (getAuth()) {
      router.replace('/');
    }
  }, [router]);

  async function onLogin(e: FormEvent) {
    e.preventDefault();
    setError('');
    try {
      const res = await api.login(email, password);
      if (res.totp_required) {
        setPreauth(res.preauth_token ?? '');
        return;
      }
      const token = res.session?.token ?? '';
      const csrf = res.csrf_token ?? '';
      if (!token || !csrf) {
        throw new Error('Login succeeded but tokens are missing.');
      }
      setAuth({ sessionToken: token, csrfToken: csrf });
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
      const token = res.session?.token ?? '';
      const csrf = res.csrf_token ?? '';
      if (!token || !csrf) {
        throw new Error('TOTP verify succeeded but tokens are missing.');
      }
      setAuth({ sessionToken: token, csrfToken: csrf });
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

      {error && <p className="error">{error}</p>}
    </section>
  );
}
