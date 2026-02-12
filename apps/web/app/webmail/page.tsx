'use client';

import Link from 'next/link';
import { FormEvent, useState } from 'react';
import { api } from '@/lib/api';
import { useAuth } from '@/components/auth-provider';

export default function WebmailPage() {
  const { me } = useAuth();
  const [mailbox, setMailbox] = useState('');
  const [password, setPassword] = useState('');
  const [wmToken, setWmToken] = useState('');
  const [messages, setMessages] = useState<Array<{ id: string; subject: string; from: string }>>([]);
  const [to, setTo] = useState('');
  const [subject, setSubject] = useState('');
  const [body, setBody] = useState('');
  const [error, setError] = useState('');

  const ready = !!me;

  async function createSession(e: FormEvent) {
    e.preventDefault();
    setError('');
    try {
      const created = await api.createWebmailSession(mailbox, password);
      setWmToken(created.token);
      const inbox = await api.getWebmailMessages(created.token, 'INBOX');
      setMessages(inbox.messages ?? []);
    } catch (err) {
      setError((err as Error).message);
    }
  }

  async function sendMessage(e: FormEvent) {
    e.preventDefault();
    setError('');
    try {
      await api.sendWebmailMessage(wmToken, to, subject, body);
      setTo('');
      setSubject('');
      setBody('');
    } catch (err) {
      setError((err as Error).message);
    }
  }

  return (
    <section className="panel">
      <h1>Custom Webmail</h1>
      <p>IMAP/SMTP proxy-backed mailbox UI for Nebula Panel.</p>

      {!ready && (
        <p className="top-gap">
          You must <Link href="/login">log in</Link> first so Nebula can authorize webmail actions.
        </p>
      )}

      <div className="grid two">
        <form onSubmit={createSession} className="stack">
          <h2>Session</h2>
          <input value={mailbox} onChange={(e) => setMailbox(e.target.value)} placeholder="Mailbox" />
          <input value={password} onChange={(e) => setPassword(e.target.value)} type="password" placeholder="Mailbox password" />
          <button className="btn btn-primary" type="submit" disabled={!ready}>Open Inbox</button>
          {wmToken ? <p className="small">Session active.</p> : null}
        </form>

        <form onSubmit={sendMessage} className="stack">
          <h2>Compose</h2>
          <input value={to} onChange={(e) => setTo(e.target.value)} placeholder="To" />
          <input value={subject} onChange={(e) => setSubject(e.target.value)} placeholder="Subject" />
          <textarea value={body} onChange={(e) => setBody(e.target.value)} placeholder="Message body" rows={7} />
          <button className="btn btn-secondary" type="submit" disabled={!ready || !wmToken}>Send</button>
        </form>
      </div>

      <div className="mail-list top-gap">
        <h2>Inbox</h2>
        {messages.length === 0 && <p>No messages loaded.</p>}
        {messages.map((m) => (
          <article key={m.id} className="mail-item">
            <p>{m.subject}</p>
            <small>{m.from}</small>
          </article>
        ))}
      </div>

      {error && <p className="error">{error}</p>}
    </section>
  );
}
