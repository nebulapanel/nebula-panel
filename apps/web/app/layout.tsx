import './globals.css';
import type { Metadata } from 'next';
import { Space_Grotesk, JetBrains_Mono } from 'next/font/google';
import { AppHeader } from '@/components/app-header';

const display = Space_Grotesk({ subsets: ['latin'], variable: '--font-display' });
const mono = JetBrains_Mono({ subsets: ['latin'], variable: '--font-mono' });

export const metadata: Metadata = {
  title: 'Nebula Panel',
  description: 'Single-server hosting control panel'
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className={`${display.variable} ${mono.variable}`}>
        <div className="nebula-bg" />
        <main className="shell">
          <AppHeader />
          {children}
        </main>
      </body>
    </html>
  );
}
