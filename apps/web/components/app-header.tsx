'use client';

import Image from 'next/image';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useEffect, useState } from 'react';

import { api } from '@/lib/api';
import { clearAuth, getAuth } from '@/lib/auth';

const links = [
  { href: '/', label: 'Dashboard' },
  { href: '/sites', label: 'Sites' },
  { href: '/dns', label: 'DNS' },
  { href: '/ssl', label: 'SSL' },
  { href: '/mail', label: 'Mail' },
  { href: '/files', label: 'Files' },
  { href: '/webmail', label: 'Webmail' },
  { href: '/backups', label: 'Backups' },
  { href: '/jobs', label: 'Jobs' }
];

export function AppHeader() {
  const router = useRouter();
  const [authed, setAuthed] = useState(false);

  useEffect(() => {
    setAuthed(!!getAuth());
  }, []);

  async function onLogout() {
    try {
      await api.logout();
    } catch {
      // best-effort logout; we still clear local state
    }
    clearAuth();
    setAuthed(false);
    router.push('/login');
    router.refresh();
  }

  return (
    <header className="app-header">
      <Link href="/" className="brand" aria-label="Nebula Panel Home">
        <Image src="/nebula-logo.png" alt="Nebula Panel" width={42} height={42} priority />
        <div className="brand-text">
          <strong>Nebula Panel</strong>
          <span>Hosting Control Surface</span>
        </div>
      </Link>

      <nav className="top-nav" aria-label="Primary">
        {links.map((link) => (
          <Link key={link.href} href={link.href}>
            {link.label}
          </Link>
        ))}
        {authed ? (
          <button type="button" onClick={onLogout}>
            Logout
          </button>
        ) : (
          <Link href="/login">Login</Link>
        )}
      </nav>
    </header>
  );
}
