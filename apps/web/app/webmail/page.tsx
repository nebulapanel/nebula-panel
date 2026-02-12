'use client';

import { FormEvent, useState } from 'react';
import { api } from '@/lib/api';

export default function WebmailPage() {
  const [panelToken, setPanelToken] = useState('');
  const [csrfToken, setCsrfToken] = useState('');
  const [mailbox, setMailbox] = useState('admin@example.com');
  const [password, setPassword] = useState('changeme');
  const [wmToken, setWmToken] = useState('');
  const [messages, setMessages] = useState<Array<{ id: string; subject: string; from: string }>>([]);
  const [to, setTo] = useState('');
  const [subject, setSubject] = useState('');
  const [body, setBody] = useState('');
  const [error, setError] = useState('');

  async function createSession(e: FormEvent) {
    e.preventDefault();
    setError('');
    try {
      const created = await api.createWebmailSession(panelToken, csrfToken, mailbox, password);
      setWmToken(created.token);
      const inbox = await api.getWebmailMessages(panelToken, created.token, 'INBOX');
      setMessages(inbox.messages ?? []);
    } catch (err) {
      setError((err as Error).message);
    }
  }

  async function sendMessage(e: FormEvent) {
    e.preventDefault();
    setError('');
    try {
      await api.sendWebmailMessage(panelToken, csrfToken, wmToken, to, subject, body);
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

      <div className="grid two">
        <form onSubmit={createSession} className="stack">
          <h2>Session</h2>
          <input value={panelToken} onChange={(e) => setPanelToken(e.target.value)} placeholder="Panel session token" />
          <input value={csrfToken} onChange={(e) => setCsrfToken(e.target.value)} placeholder="CSRF token" />
          <input value={mailbox} onChange={(e) => setMailbox(e.target.value)} placeholder="Mailbox" />
          <input value={password} onChange={(e) => setPassword(e.target.value)} type="password" placeholder="Mailbox password" />
          <button className="btn btn-primary" type="submit">Open Inbox</button>
          {wmToken && <code>{wmToken}</code>}
        </form>

        <form onSubmit={sendMessage} className="stack">
          <h2>Compose</h2>
          <input value={to} onChange={(e) => setTo(e.target.value)} placeholder="To" />
          <input value={subject} onChange={(e) => setSubject(e.target.value)} placeholder="Subject" />
          <textarea value={body} onChange={(e) => setBody(e.target.value)} placeholder="Message body" rows={7} />
          <button className="btn btn-secondary" type="submit">Send</button>
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
