package models

import "time"

type Role string

const (
	RoleAdmin Role = "admin"
	RoleUser  Role = "user"
)

type User struct {
	ID            string    `json:"id"`
	Email         string    `json:"email"`
	Role          Role      `json:"role"`
	LinuxUsername string    `json:"linux_username"`
	SFTPEnabled   bool      `json:"sftp_enabled"`
	PasswordHash  string    `json:"-"`
	CreatedAt     time.Time `json:"created_at"`
}

type Session struct {
	Token     string    `json:"token"`
	UserID    string    `json:"user_id"`
	Role      Role      `json:"role"`
	ExpiresAt time.Time `json:"expires_at"`
}

type Site struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Domain    string    `json:"domain"`
	OwnerID   string    `json:"owner_id"`
	RootPath  string    `json:"root_path"`
	CreatedAt time.Time `json:"created_at"`
}

type Database struct {
	ID        string    `json:"id"`
	SiteID    string    `json:"site_id"`
	Engine    string    `json:"engine"`
	Name      string    `json:"name"`
	Username  string    `json:"username"`
	CreatedAt time.Time `json:"created_at"`
}

type SSLStatus struct {
	SiteID      string    `json:"site_id"`
	Provider    string    `json:"provider"`
	Status      string    `json:"status"`
	ExpiresAt   time.Time `json:"expires_at"`
	LastError   string    `json:"last_error,omitempty"`
	UpdatedAt   time.Time `json:"updated_at"`
	Certificate string    `json:"certificate,omitempty"`
}

type DNSRecord struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Name     string `json:"name"`
	Value    string `json:"value"`
	TTL      int    `json:"ttl"`
	Priority int    `json:"priority,omitempty"`
}

type DNSZone struct {
	Zone      string      `json:"zone"`
	OwnerID   string      `json:"owner_id,omitempty"`
	Serial    int64       `json:"serial"`
	CreatedAt time.Time   `json:"created_at"`
	Records   []DNSRecord `json:"records"`
}

type MailDomain struct {
	Domain    string    `json:"domain"`
	OwnerID   string    `json:"owner_id,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type Mailbox struct {
	ID        string    `json:"id"`
	Domain    string    `json:"domain"`
	Address   string    `json:"address"`
	Password  string    `json:"-"`
	QuotaMB   int       `json:"quota_mb"`
	CreatedAt time.Time `json:"created_at"`
}

type MailAlias struct {
	ID          string    `json:"id"`
	Domain      string    `json:"domain"`
	Source      string    `json:"source"`
	Destination string    `json:"destination"`
	CreatedAt   time.Time `json:"created_at"`
}

type WebmailToken struct {
	Token     string    `json:"token"`
	Mailbox   string    `json:"mailbox"`
	ExpiresAt time.Time `json:"expires_at"`
}

type WebmailMessage struct {
	ID        string    `json:"id"`
	Folder    string    `json:"folder"`
	From      string    `json:"from"`
	To        string    `json:"to"`
	Subject   string    `json:"subject"`
	Body      string    `json:"body"`
	CreatedAt time.Time `json:"created_at"`
}

type MailSendLog struct {
	ID        string    `json:"id"`
	From      string    `json:"from"`
	To        string    `json:"to"`
	Subject   string    `json:"subject"`
	CreatedAt time.Time `json:"created_at"`
}

type Backup struct {
	ID         string    `json:"id"`
	Scope      string    `json:"scope"`
	Status     string    `json:"status"`
	BucketPath string    `json:"bucket_path"`
	CreatedAt  time.Time `json:"created_at"`
}

type Job struct {
	ID         string    `json:"id"`
	Type       string    `json:"type"`
	Status     string    `json:"status"`
	TargetID   string    `json:"target_id"`
	Message    string    `json:"message,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	FinishedAt time.Time `json:"finished_at,omitempty"`
}

type JobEvent struct {
	ID        string    `json:"id"`
	JobID     string    `json:"job_id"`
	Status    string    `json:"status"`
	Message   string    `json:"message,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type AuditLog struct {
	ID        string    `json:"id"`
	ActorID   string    `json:"actor_id"`
	Action    string    `json:"action"`
	Target    string    `json:"target"`
	Summary   string    `json:"summary"`
	CreatedAt time.Time `json:"created_at"`
}

type TaskRequest struct {
	Type   string            `json:"type"`
	Target string            `json:"target"`
	Args   map[string]string `json:"args"`
}
