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
