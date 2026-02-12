import Link from 'next/link';
import { ModuleCard } from '@/components/module-card';

const modules = [
  { title: 'Sites', href: '/sites', text: 'Provision domains, Nginx, PHP-FPM, and DB runtime.' },
  { title: 'DNS', href: '/dns', text: 'Manage authoritative records via PowerDNS integration.' },
  { title: 'SSL', href: '/ssl', text: 'Issue and renew free certificates automatically.' },
  { title: 'Mail', href: '/mail', text: 'Manage domains, mailboxes, aliases, DKIM/SPF/DMARC.' },
  { title: 'Files', href: '/files', text: 'Browser file manager with jailed filesystem access.' },
  { title: 'Backups', href: '/backups', text: 'Encrypted snapshots to S3-compatible storage.' },
  { title: 'Webmail', href: '/webmail', text: 'Custom mailbox UI through IMAP/SMTP proxy API.' },
  { title: 'Jobs & Audit', href: '/jobs', text: 'Observe async provisioning and security event history.' }
];

export default function HomePage() {
  return (
    <section>
      <header className="hero">
        <p className="eyebrow">Nebula Panel</p>
        <h1>Operate web hosting, DNS, SSL, and mail from one control surface.</h1>
        <p>
          Single-server control plane with role-based access, signed task execution, and deployment-first workflows.
        </p>
        <div className="actions">
          <Link href="/login" className="btn btn-primary">Admin Login</Link>
          <Link href="/webmail" className="btn btn-secondary">Open Webmail</Link>
        </div>
      </header>

      <section className="grid">
        {modules.map((mod) => (
          <ModuleCard key={mod.title} {...mod} />
        ))}
      </section>
    </section>
  );
}
