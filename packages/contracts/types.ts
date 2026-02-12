export type Role = 'admin' | 'user';

export interface Session {
  token: string;
  user_id: string;
  role: Role;
  expires_at: string;
}

export interface User {
  id: string;
  email: string;
  role: Role;
  linux_username: string;
  sftp_enabled: boolean;
  created_at: string;
}

export interface Site {
  id: string;
  name: string;
  domain: string;
  owner_id: string;
  root_path: string;
  created_at: string;
}

export interface Database {
  id: string;
  site_id: string;
  engine: string;
  name: string;
  username: string;
  created_at: string;
}

export interface Job {
  id: string;
  type: string;
  status: string;
  target_id: string;
  message?: string;
  created_at: string;
  finished_at?: string;
}

export interface JobEvent {
  id: string;
  job_id: string;
  status: string;
  message?: string;
  created_at: string;
}
