package http

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/nebula-panel/nebula/apps/api/internal/config"
	apimw "github.com/nebula-panel/nebula/apps/api/internal/middleware"
	"github.com/nebula-panel/nebula/apps/api/internal/models"
	"github.com/nebula-panel/nebula/apps/api/internal/security"
	"github.com/nebula-panel/nebula/apps/api/internal/store"
	"github.com/nebula-panel/nebula/apps/api/internal/tasks"
)

type Server struct {
	cfg   config.Config
	st    *store.Store
	tasks *tasks.Client
}

func NewServer(cfg config.Config, st *store.Store) *Server {
	return &Server{cfg: cfg, st: st, tasks: tasks.New(cfg.AgentSocket, cfg.AgentSharedSecret)}
}

func (s *Server) Router() http.Handler {
	r := chi.NewRouter()
	r.Use(chimw.RequestID)
	r.Use(chimw.RealIP)
	r.Use(chimw.Logger)
	r.Use(chimw.Recoverer)

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "service": "nebula-api"})
	})

	r.Route("/v1", func(r chi.Router) {
		r.Post("/auth/login", s.handleLogin)
		r.Post("/auth/totp/verify", s.handleTOTPVerify)
		r.Post("/auth/logout", s.handleLogout)

		r.Group(func(r chi.Router) {
			r.Use(apimw.RequireSession(s.st))
			r.Use(s.csrfMiddleware)

			r.Post("/users", s.handleCreateUser)
			r.Get("/users", s.handleListUsers)
			r.Patch("/users/{id}", s.handleUpdateUser)
			r.Delete("/users/{id}", s.handleDeleteUser)

			r.Post("/sites", s.handleCreateSite)
			r.Get("/sites/{id}", s.handleGetSite)
			r.Delete("/sites/{id}", s.handleDeleteSite)

			r.Post("/sites/{id}/databases", s.handleCreateDB)
			r.Delete("/databases/{id}", s.handleDeleteDB)

			r.Post("/sites/{id}/ssl/issue", s.handleIssueSSL)
			r.Post("/sites/{id}/ssl/renew", s.handleRenewSSL)
			r.Get("/sites/{id}/ssl/status", s.handleSSLStatus)

			r.Post("/dns/zones", s.handleCreateZone)
			r.Get("/dns/zones/{zone}", s.handleGetZone)
			r.Put("/dns/zones/{zone}/records", s.handleReplaceZoneRecords)
			r.Delete("/dns/zones/{zone}/records/{id}", s.handleDeleteZoneRecord)

			r.Get("/files/tree", s.handleFilesTree)
			r.Post("/files/upload", s.handleFileUpload)
			r.Post("/files/mkdir", s.handleFileMkdir)
			r.Patch("/files/chmod", s.handleFileChmod)
			r.Delete("/files", s.handleFileDelete)

			r.Post("/mail/domains", s.handleCreateMailDomain)
			r.Post("/mail/domains/{domain}/mailboxes", s.handleCreateMailbox)
			r.Post("/mail/aliases", s.handleCreateAlias)
			r.Delete("/mail/mailboxes/{id}", s.handleDeleteMailbox)

			r.Post("/webmail/session", s.handleCreateWebmailSession)
			r.Get("/webmail/folders", s.handleWebmailFolders)
			r.Get("/webmail/messages", s.handleWebmailMessages)
			r.Post("/webmail/messages/send", s.handleWebmailSend)

			r.Post("/backups/run", s.handleBackupRun)
			r.Get("/backups", s.handleBackupList)
			r.Post("/backups/{id}/restore", s.handleBackupRestore)

			r.Get("/jobs/{id}", s.handleGetJob)
			r.Get("/audit-logs", s.handleAuditLogs)
		})
	})

	return r
}

func (s *Server) csrfMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		cookie, err := r.Cookie("nebula_csrf")
		if err != nil || cookie.Value == "" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if r.Header.Get("X-CSRF-Token") != cookie.Value {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) setCSRFCookie(w http.ResponseWriter) string {
	v := uuid.NewString()
	http.SetCookie(w, &http.Cookie{
		Name:     "nebula_csrf",
		Value:    v,
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Now().Add(24 * time.Hour),
	})
	return v
}

func (s *Server) currentSession(r *http.Request) (models.Session, error) {
	sess, ok := apimw.SessionFromContext(r.Context())
	if !ok {
		return models.Session{}, errors.New("missing session")
	}
	return sess, nil
}

func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) (models.Session, bool) {
	sess, err := s.currentSession(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return models.Session{}, false
	}
	if sess.Role != models.RoleAdmin {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin role required"})
		return models.Session{}, false
	}
	return sess, true
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	u, ok := s.st.CheckUserPassword(req.Email, req.Password)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}

	csrf := s.setCSRFCookie(w)
	if u.Role == models.RoleAdmin {
		preauth := s.st.CreatePreAuth(u.ID)
		writeJSON(w, http.StatusOK, map[string]any{
			"totp_required": true,
			"preauth_token": preauth,
			"csrf_token":    csrf,
		})
		return
	}

	sess, err := s.st.CreateSession(u.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"session": sess, "csrf_token": csrf})
}

func (s *Server) handleTOTPVerify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PreAuthToken string `json:"preauth_token"`
		Code         string `json:"code"`
	}
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if req.Code != s.cfg.AdminTOTPCode {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid totp code"})
		return
	}
	uid, ok := s.st.ConsumePreAuth(req.PreAuthToken)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid preauth token"})
		return
	}
	sess, err := s.st.CreateSession(uid)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	csrf := s.setCSRFCookie(w)
	writeJSON(w, http.StatusOK, map[string]any{"session": sess, "csrf_token": csrf})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SessionToken string `json:"session_token"`
	}
	_ = readJSON(r, &req)
	if req.SessionToken != "" {
		s.st.DeleteSession(req.SessionToken)
	}
	writeJSON(w, http.StatusNoContent, nil)
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	var req struct {
		Email    string      `json:"email"`
		Password string      `json:"password"`
		Role     models.Role `json:"role"`
	}
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if req.Role == "" {
		req.Role = models.RoleUser
	}
	u, err := s.st.CreateUser(req.Email, req.Password, req.Role)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	s.st.AddAudit(sess.UserID, "create_user", u.ID, "Created user account")
	writeJSON(w, http.StatusCreated, u)
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": s.st.ListUsers()})
}

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	var req struct {
		Role models.Role `json:"role"`
	}
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	u, err := s.st.UpdateUser(chi.URLParam(r, "id"), req.Role)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	s.st.AddAudit(sess.UserID, "update_user", u.ID, "Updated user role")
	writeJSON(w, http.StatusOK, u)
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	id := chi.URLParam(r, "id")
	s.st.DeleteUser(id)
	s.st.AddAudit(sess.UserID, "delete_user", id, "Deleted user")
	writeJSON(w, http.StatusNoContent, nil)
}

func (s *Server) handleCreateSite(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	var req struct {
		Name    string `json:"name"`
		Domain  string `json:"domain"`
		OwnerID string `json:"owner_id"`
	}
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	site, err := s.st.CreateSite(req.Name, req.Domain, req.OwnerID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	job := s.st.CreateJob("site_create", site.ID, "queued")
	if err := s.tasks.Submit(r.Context(), tasks.Request{Type: "site_create", Target: site.ID, Args: map[string]string{"domain": site.Domain, "owner_id": site.OwnerID}}); err != nil {
		s.st.UpdateJobStatus(job.ID, "failed", err.Error())
	} else {
		s.st.UpdateJobStatus(job.ID, "done", "site provisioned")
	}
	job, _ = s.st.GetJob(job.ID)
	s.st.AddAudit(sess.UserID, "create_site", site.ID, fmt.Sprintf("Created site for domain %s", site.Domain))
	writeJSON(w, http.StatusCreated, map[string]any{"site": site, "job": job})
}

func (s *Server) handleGetSite(w http.ResponseWriter, r *http.Request) {
	site, ok := s.st.GetSite(chi.URLParam(r, "id"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "site not found"})
		return
	}
	writeJSON(w, http.StatusOK, site)
}

func (s *Server) handleDeleteSite(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	id := chi.URLParam(r, "id")
	job := s.st.CreateJob("site_delete", id, "queued")
	if err := s.tasks.Submit(r.Context(), tasks.Request{Type: "site_delete", Target: id}); err != nil {
		s.st.UpdateJobStatus(job.ID, "failed", err.Error())
	} else {
		s.st.UpdateJobStatus(job.ID, "done", "site deleted")
		s.st.DeleteSite(id)
	}
	job, _ = s.st.GetJob(job.ID)
	s.st.AddAudit(sess.UserID, "delete_site", id, "Deleted site")
	writeJSON(w, http.StatusAccepted, map[string]any{"job": job})
}

func (s *Server) handleCreateDB(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	var req struct {
		Engine   string `json:"engine"`
		Name     string `json:"name"`
		Username string `json:"username"`
	}
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	db, err := s.st.CreateDatabase(chi.URLParam(r, "id"), req.Engine, req.Name, req.Username)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	s.st.AddAudit(sess.UserID, "create_database", db.ID, "Created database")
	writeJSON(w, http.StatusCreated, db)
}

func (s *Server) handleDeleteDB(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	id := chi.URLParam(r, "id")
	s.st.DeleteDatabase(id)
	s.st.AddAudit(sess.UserID, "delete_database", id, "Deleted database")
	writeJSON(w, http.StatusNoContent, nil)
}

func (s *Server) handleIssueSSL(w http.ResponseWriter, r *http.Request) {
	s.handleSSLTask(w, r, "ssl_issue", "issued")
}

func (s *Server) handleRenewSSL(w http.ResponseWriter, r *http.Request) {
	s.handleSSLTask(w, r, "ssl_renew", "renewed")
}

func (s *Server) handleSSLTask(w http.ResponseWriter, r *http.Request, taskType, endStatus string) {
	sess, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	siteID := chi.URLParam(r, "id")
	site, ok := s.st.GetSite(siteID)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "site not found"})
		return
	}
	job := s.st.CreateJob(taskType, siteID, "queued")
	err := s.tasks.Submit(r.Context(), tasks.Request{
		Type:   taskType,
		Target: siteID,
		Args: map[string]string{
			"provider": "letsencrypt",
			"domain":   site.Domain,
			"email":    s.cfg.ACMEEmail,
		},
	})
	if err == nil {
		s.st.UpdateJobStatus(job.ID, "done", endStatus)
		s.st.SetSSLStatus(siteID, "letsencrypt", "active", "", time.Now().UTC().Add(85*24*time.Hour))
	} else {
		fallbackErr := s.tasks.Submit(r.Context(), tasks.Request{
			Type:   taskType,
			Target: siteID,
			Args: map[string]string{
				"provider": "zerossl",
				"domain":   site.Domain,
				"email":    s.cfg.ACMEEmail,
			},
		})
		if fallbackErr != nil {
			s.st.UpdateJobStatus(job.ID, "failed", "letsencrypt: "+err.Error()+"; zerossl: "+fallbackErr.Error())
			s.st.SetSSLStatus(siteID, "zerossl", "failed", fallbackErr.Error(), time.Time{})
		} else {
			s.st.UpdateJobStatus(job.ID, "done", endStatus+" via zerossl fallback")
			s.st.SetSSLStatus(siteID, "zerossl", "active", "", time.Now().UTC().Add(85*24*time.Hour))
		}
	}
	job, _ = s.st.GetJob(job.ID)
	s.st.AddAudit(sess.UserID, taskType, siteID, "Triggered SSL workflow")
	writeJSON(w, http.StatusAccepted, map[string]any{"job": job})
}

func (s *Server) handleSSLStatus(w http.ResponseWriter, r *http.Request) {
	st, ok := s.st.GetSSLStatus(chi.URLParam(r, "id"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "ssl status not found"})
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleCreateZone(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	var req struct {
		Zone string `json:"zone"`
	}
	if err := readJSON(r, &req); err != nil || req.Zone == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "zone is required"})
		return
	}
	records := []models.DNSRecord{
		{ID: "r_" + uuid.NewString(), Type: "NS", Name: req.Zone, Value: "ns1." + req.Zone, TTL: 3600},
		{ID: "r_" + uuid.NewString(), Type: "NS", Name: req.Zone, Value: "ns2." + req.Zone, TTL: 3600},
	}
	z := s.st.CreateZone(req.Zone, records)
	job := s.st.CreateJob("dns_apply", req.Zone, "queued")
	if err := s.submitDNSApply(r, z); err != nil {
		s.st.UpdateJobStatus(job.ID, "failed", err.Error())
	} else {
		s.st.UpdateJobStatus(job.ID, "done", "zone applied")
	}
	job, _ = s.st.GetJob(job.ID)
	s.st.AddAudit(sess.UserID, "create_dns_zone", req.Zone, "Created DNS zone")
	writeJSON(w, http.StatusCreated, map[string]any{"zone": z, "job": job})
}

func (s *Server) handleGetZone(w http.ResponseWriter, r *http.Request) {
	z, ok := s.st.GetZone(chi.URLParam(r, "zone"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "zone not found"})
		return
	}
	writeJSON(w, http.StatusOK, z)
}

func (s *Server) handleReplaceZoneRecords(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	var req struct {
		Records []models.DNSRecord `json:"records"`
	}
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	for i := range req.Records {
		if req.Records[i].ID == "" {
			req.Records[i].ID = "r_" + uuid.NewString()
		}
	}
	z, err := s.st.ReplaceZoneRecords(chi.URLParam(r, "zone"), req.Records)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	job := s.st.CreateJob("dns_apply", z.Zone, "queued")
	if err := s.submitDNSApply(r, z); err != nil {
		s.st.UpdateJobStatus(job.ID, "failed", err.Error())
	} else {
		s.st.UpdateJobStatus(job.ID, "done", "zone applied")
	}
	job, _ = s.st.GetJob(job.ID)
	s.st.AddAudit(sess.UserID, "replace_dns_records", z.Zone, "Replaced DNS records")
	writeJSON(w, http.StatusOK, map[string]any{"zone": z, "job": job})
}

func (s *Server) handleDeleteZoneRecord(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	z, err := s.st.DeleteZoneRecord(chi.URLParam(r, "zone"), chi.URLParam(r, "id"))
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	job := s.st.CreateJob("dns_apply", z.Zone, "queued")
	if err := s.submitDNSApply(r, z); err != nil {
		s.st.UpdateJobStatus(job.ID, "failed", err.Error())
	} else {
		s.st.UpdateJobStatus(job.ID, "done", "zone applied")
	}
	job, _ = s.st.GetJob(job.ID)
	s.st.AddAudit(sess.UserID, "delete_dns_record", z.Zone, "Deleted DNS record")
	writeJSON(w, http.StatusOK, map[string]any{"zone": z, "job": job})
}

func (s *Server) handleFilesTree(w http.ResponseWriter, r *http.Request) {
	sess, err := s.currentSession(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	root := s.userRoot(sess)
	if err := os.MkdirAll(root, s.cfg.FilePermMask); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	target, err := security.SafeJoin(root, r.URL.Query().Get("path"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := security.CheckSymlinkEscape(root, target); err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
		return
	}
	entries, err := os.ReadDir(target)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "path not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	resp := make([]map[string]any, 0, len(entries))
	for _, e := range entries {
		info, _ := e.Info()
		resp = append(resp, map[string]any{"name": e.Name(), "is_dir": e.IsDir(), "size": info.Size(), "mod_time": info.ModTime()})
	}
	writeJSON(w, http.StatusOK, map[string]any{"path": target, "entries": resp})
}

func (s *Server) handleFileUpload(w http.ResponseWriter, r *http.Request) {
	sess, err := s.currentSession(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	var req struct {
		Path          string `json:"path"`
		ContentBase64 string `json:"content_base64"`
	}
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	root := s.userRoot(sess)
	target, err := security.SafeJoin(root, req.Path)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := os.MkdirAll(filepath.Dir(target), s.cfg.FilePermMask); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	decoded, err := base64.StdEncoding.DecodeString(req.ContentBase64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid base64 content"})
		return
	}
	if err := os.WriteFile(target, decoded, 0o640); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	s.st.AddAudit(sess.UserID, "file_upload", target, "Uploaded file")
	writeJSON(w, http.StatusCreated, map[string]any{"path": target, "bytes": len(decoded)})
}

func (s *Server) handleFileMkdir(w http.ResponseWriter, r *http.Request) {
	sess, err := s.currentSession(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	var req struct {
		Path string `json:"path"`
	}
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	root := s.userRoot(sess)
	target, err := security.SafeJoin(root, req.Path)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := os.MkdirAll(target, s.cfg.FilePermMask); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	s.st.AddAudit(sess.UserID, "file_mkdir", target, "Created directory")
	writeJSON(w, http.StatusCreated, map[string]any{"path": target})
}

func (s *Server) handleFileChmod(w http.ResponseWriter, r *http.Request) {
	sess, err := s.currentSession(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	var req struct {
		Path string `json:"path"`
		Mode string `json:"mode"`
	}
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	root := s.userRoot(sess)
	target, err := security.SafeJoin(root, req.Path)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	modeNum, err := strconv.ParseUint(req.Mode, 8, 32)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "mode must be octal string, e.g. 640"})
		return
	}
	if err := os.Chmod(target, os.FileMode(modeNum)); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	s.st.AddAudit(sess.UserID, "file_chmod", target, "Changed permissions")
	writeJSON(w, http.StatusOK, map[string]any{"path": target, "mode": req.Mode})
}

func (s *Server) handleFileDelete(w http.ResponseWriter, r *http.Request) {
	sess, err := s.currentSession(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	var req struct {
		Path string `json:"path"`
	}
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	root := s.userRoot(sess)
	target, err := security.SafeJoin(root, req.Path)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := os.RemoveAll(target); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	s.st.AddAudit(sess.UserID, "file_delete", target, "Deleted file/directory")
	writeJSON(w, http.StatusNoContent, nil)
}

func (s *Server) handleCreateMailDomain(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	var req struct {
		Domain string `json:"domain"`
	}
	if err := readJSON(r, &req); err != nil || req.Domain == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "domain is required"})
		return
	}
	domain, err := s.st.CreateMailDomain(req.Domain)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	job := s.st.CreateJob("mail_apply", req.Domain, "queued")
	if err := s.submitMailApply(r); err != nil {
		s.st.UpdateJobStatus(job.ID, "failed", err.Error())
	} else {
		s.st.UpdateJobStatus(job.ID, "done", "mail config regenerated")
	}
	job, _ = s.st.GetJob(job.ID)
	s.st.AddAudit(sess.UserID, "create_mail_domain", req.Domain, "Created mail domain")
	writeJSON(w, http.StatusCreated, map[string]any{"domain": domain, "job": job})
}

func (s *Server) handleCreateMailbox(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	var req struct {
		LocalPart string `json:"local_part"`
		Password  string `json:"password"`
		QuotaMB   int    `json:"quota_mb"`
	}
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if req.QuotaMB <= 0 {
		req.QuotaMB = 2048
	}
	if req.Password == "" {
		req.Password = uuid.NewString()[:16]
	}
	mb, err := s.st.CreateMailbox(chi.URLParam(r, "domain"), req.LocalPart, req.Password, req.QuotaMB)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	job := s.st.CreateJob("mail_apply", "mail", "queued")
	if err := s.submitMailApply(r); err != nil {
		s.st.UpdateJobStatus(job.ID, "failed", err.Error())
	} else {
		s.st.UpdateJobStatus(job.ID, "done", "mail config regenerated")
	}
	job, _ = s.st.GetJob(job.ID)
	s.st.AddAudit(sess.UserID, "create_mailbox", mb.ID, "Created mailbox")
	writeJSON(w, http.StatusCreated, map[string]any{"mailbox": mb, "job": job, "generated_password": req.Password})
}

func (s *Server) handleCreateAlias(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	var req struct {
		Domain      string `json:"domain"`
		Source      string `json:"source"`
		Destination string `json:"destination"`
	}
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	a, err := s.st.CreateAlias(req.Domain, req.Source, req.Destination)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	job := s.st.CreateJob("mail_apply", "mail", "queued")
	if err := s.submitMailApply(r); err != nil {
		s.st.UpdateJobStatus(job.ID, "failed", err.Error())
	} else {
		s.st.UpdateJobStatus(job.ID, "done", "mail config regenerated")
	}
	job, _ = s.st.GetJob(job.ID)
	s.st.AddAudit(sess.UserID, "create_alias", a.ID, "Created alias")
	writeJSON(w, http.StatusCreated, map[string]any{"alias": a, "job": job})
}

func (s *Server) handleDeleteMailbox(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	id := chi.URLParam(r, "id")
	s.st.DeleteMailbox(id)
	job := s.st.CreateJob("mail_apply", "mail", "queued")
	if err := s.submitMailApply(r); err != nil {
		s.st.UpdateJobStatus(job.ID, "failed", err.Error())
	} else {
		s.st.UpdateJobStatus(job.ID, "done", "mail config regenerated")
	}
	job, _ = s.st.GetJob(job.ID)
	s.st.AddAudit(sess.UserID, "delete_mailbox", id, "Deleted mailbox")
	writeJSON(w, http.StatusOK, map[string]any{"job": job})
}

func (s *Server) handleCreateWebmailSession(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Mailbox  string `json:"mailbox"`
		Password string `json:"password"`
	}
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if req.Mailbox == "" || req.Password == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "mailbox and password required"})
		return
	}
	tok, err := s.st.CreateWebmailSession(strings.ToLower(req.Mailbox), 2*time.Hour)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, tok)
}

func (s *Server) webmailMailbox(r *http.Request) (string, bool) {
	tok := r.Header.Get("X-Webmail-Token")
	if tok == "" {
		return "", false
	}
	wt, ok := s.st.GetWebmailSession(tok)
	if !ok {
		return "", false
	}
	return wt.Mailbox, true
}

func (s *Server) handleWebmailFolders(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.webmailMailbox(r); !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid webmail token"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"folders": []string{"INBOX", "Sent", "Drafts", "Trash"}})
}

func (s *Server) handleWebmailMessages(w http.ResponseWriter, r *http.Request) {
	mailbox, ok := s.webmailMailbox(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid webmail token"})
		return
	}
	folder := r.URL.Query().Get("folder")
	if folder == "" {
		folder = "INBOX"
	}
	msgs := s.st.ListMailboxMessages(mailbox, folder)
	writeJSON(w, http.StatusOK, map[string]any{"messages": msgs})
}

func (s *Server) handleWebmailSend(w http.ResponseWriter, r *http.Request) {
	mailbox, ok := s.webmailMailbox(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid webmail token"})
		return
	}
	var req struct {
		To      string `json:"to"`
		Subject string `json:"subject"`
		Body    string `json:"body"`
	}
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	msg := s.st.SaveSentMessage(mailbox, req.To, req.Subject, req.Body)
	writeJSON(w, http.StatusCreated, msg)
}

func (s *Server) handleBackupRun(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	var req struct {
		Scope string `json:"scope"`
	}
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if req.Scope == "" {
		req.Scope = "full"
	}
	b := s.st.CreateBackup(req.Scope)
	job := s.st.CreateJob("backup_run", b.ID, "queued")
	if err := s.tasks.Submit(r.Context(), tasks.Request{Type: "backup_run", Target: b.ID, Args: map[string]string{"scope": req.Scope}}); err != nil {
		s.st.UpdateJobStatus(job.ID, "failed", err.Error())
	} else {
		s.st.UpdateJobStatus(job.ID, "done", "backup completed")
	}
	job, _ = s.st.GetJob(job.ID)
	s.st.AddAudit(sess.UserID, "backup_run", b.ID, "Triggered backup")
	writeJSON(w, http.StatusAccepted, map[string]any{"backup": b, "job": job})
}

func (s *Server) handleBackupList(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"backups": s.st.ListBackups()})
}

func (s *Server) handleBackupRestore(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	id := chi.URLParam(r, "id")
	if _, ok := s.st.GetBackup(id); !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "backup not found"})
		return
	}
	job := s.st.CreateJob("backup_restore", id, "queued")
	if err := s.tasks.Submit(r.Context(), tasks.Request{Type: "backup_restore", Target: id}); err != nil {
		s.st.UpdateJobStatus(job.ID, "failed", err.Error())
	} else {
		s.st.UpdateJobStatus(job.ID, "done", "backup restored")
	}
	job, _ = s.st.GetJob(job.ID)
	s.st.AddAudit(sess.UserID, "backup_restore", id, "Triggered restore")
	writeJSON(w, http.StatusAccepted, map[string]any{"job": job})
}

func (s *Server) handleGetJob(w http.ResponseWriter, r *http.Request) {
	job, ok := s.st.GetJob(chi.URLParam(r, "id"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "job not found"})
		return
	}
	writeJSON(w, http.StatusOK, job)
}

func (s *Server) handleAuditLogs(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"logs": s.st.ListAudit()})
}

func (s *Server) userRoot(sess models.Session) string {
	return filepath.Join(s.cfg.DataRoot, "users", sess.UserID)
}

func (s *Server) submitDNSApply(r *http.Request, zone models.DNSZone) error {
	recordsJSON, err := json.Marshal(zone.Records)
	if err != nil {
		return err
	}
	return s.tasks.Submit(r.Context(), tasks.Request{
		Type:   "dns_apply",
		Target: zone.Zone,
		Args: map[string]string{
			"zone":         zone.Zone,
			"records_json": string(recordsJSON),
		},
	})
}

func (s *Server) submitMailApply(r *http.Request) error {
	domains, err := s.st.ListMailDomains()
	if err != nil {
		return err
	}
	mailboxes, err := s.st.ListMailboxes()
	if err != nil {
		return err
	}
	aliases, err := s.st.ListAliases()
	if err != nil {
		return err
	}
	domainsJSON, err := json.Marshal(domains)
	if err != nil {
		return err
	}
	mailboxesJSON, err := json.Marshal(mailboxes)
	if err != nil {
		return err
	}
	aliasesJSON, err := json.Marshal(aliases)
	if err != nil {
		return err
	}
	return s.tasks.Submit(r.Context(), tasks.Request{
		Type:   "mail_apply",
		Target: "mail",
		Args: map[string]string{
			"domains_json":   string(domainsJSON),
			"mailboxes_json": string(mailboxesJSON),
			"aliases_json":   string(aliasesJSON),
		},
	})
}
