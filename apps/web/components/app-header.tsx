import Image from 'next/image';
import Link from 'next/link';

const links = [
  { href: '/', label: 'Dashboard' },
  { href: '/sites', label: 'Sites' },
  { href: '/dns', label: 'DNS' },
  { href: '/ssl', label: 'SSL' },
  { href: '/mail', label: 'Mail' },
  { href: '/files', label: 'Files' },
  { href: '/webmail', label: 'Webmail' },
  { href: '/backups', label: 'Backups' },
  { href: '/jobs', label: 'Jobs' },
  { href: '/login', label: 'Login' }
];

export function AppHeader() {
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
      </nav>
    </header>
  );
}
