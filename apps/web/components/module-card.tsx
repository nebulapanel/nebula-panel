import Link from 'next/link';

export function ModuleCard({ title, href, text }: { title: string; href: string; text: string }) {
  return (
    <Link href={href} className="module-card">
      <h3>{title}</h3>
      <p>{text}</p>
    </Link>
  );
}
