'use client';

import Image from 'next/image';
import Link from 'next/link';
import { useRouter } from 'next/navigation';

import { useAuth } from '@/components/auth-provider';

const commonLinks = [
  { href: '/', label: 'Dashboard' },
  { href: '/sites', label: 'Sites' },
  { href: '/dns', label: 'DNS' },
  { href: '/ssl', label: 'SSL' },
  { href: '/mail', label: 'Mail' },
  { href: '/files', label: 'Files' },
  { href: '/webmail', label: 'Webmail' },
  { href: '/backups', label: 'Backups' },
  { href: '/jobs', label: 'Jobs' },
  { href: '/settings/security', label: 'Settings' }
];

export function AppHeader() {
  const router = useRouter();
  const { me, loading, logout } = useAuth();

  async function onLogout() {
    await logout();
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
        {(me
          ? [
              ...(me.role === 'admin' ? [{ href: '/users', label: 'Users' }] : []),
              ...commonLinks
            ]
          : [{ href: '/', label: 'Dashboard' }]
        ).map((link) => (
          <Link key={link.href} href={link.href}>
            {link.label}
          </Link>
        ))}
        {me ? (
          <button type="button" onClick={onLogout}>
            Logout
          </button>
        ) : loading ? null : (
          <Link href="/login">Login</Link>
        )}
      </nav>
    </header>
  );
}
