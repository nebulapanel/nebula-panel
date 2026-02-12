package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nebula-panel/nebula/apps/agent/internal/config"
	"github.com/nebula-panel/nebula/packages/lib/validate"
)

type Task struct {
	Type   string            `json:"type"`
	Target string            `json:"target"`
	Args   map[string]string `json:"args"`
}

type Executor struct {
	cfg        config.Config
	httpClient *http.Client
	allowlist  map[string]bool
}

type dnsRecord struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Name     string `json:"name"`
	Value    string `json:"value"`
	TTL      int    `json:"ttl"`
	Priority int    `json:"priority,omitempty"`
}

type mailDomain struct {
	Domain string `json:"domain"`
}

type mailMailbox struct {
	Address  string `json:"address"`
	Domain   string `json:"domain"`
	Password string `json:"password"`
}

type mailAlias struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
}

type pdnsRecord struct {
	Content  string `json:"content"`
	Disabled bool   `json:"disabled"`
}

type pdnsRRset struct {
	Name       string       `json:"name"`
	Type       string       `json:"type"`
	TTL        uint32       `json:"ttl"`
	ChangeType string       `json:"changetype,omitempty"`
	Records    []pdnsRecord `json:"records,omitempty"`
}

type pdnsZoneResponse struct {
	Name   string      `json:"name"`
	RRsets []pdnsRRset `json:"rrsets"`
}

func New(cfg config.Config) *Executor {
	return &Executor{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: 20 * time.Second,
		},
		allowlist: map[string]bool{
			"user_provision": true,
			"user_rotate_password": true,
			"db_create_mariadb": true,
			"db_delete_mariadb": true,
			"db_create_postgres": true,
			"db_delete_postgres": true,
			"site_create":    true,
			"site_delete":    true,
			"ssl_issue":      true,
			"ssl_renew":      true,
			"dns_apply":      true,
			"dns_delete":     true,
			"mail_apply":     true,
			"backup_run":     true,
			"backup_restore": true,
			"service_reload": true,
		},
	}
}

func (e *Executor) Execute(ctx context.Context, t Task) error {
	if !e.allowlist[t.Type] {
		return fmt.Errorf("task type not allowed: %s", t.Type)
	}

	switch t.Type {
	case "user_provision", "user_rotate_password":
		linuxUsername := strings.TrimSpace(t.Args["linux_username"])
		if linuxUsername == "" {
			return errors.New("linux_username is required")
		}
		if err := validate.ValidateLinuxUsername(linuxUsername); err != nil {
			return err
		}
		password := strings.TrimSpace(t.Args["password"])
		if e.cfg.DryRun {
			log.Printf("[dry-run] %s linux_username=%s", t.Type, linuxUsername)
			return nil
		}
		if err := e.ensureLinuxUser(ctx, linuxUsername); err != nil {
			return err
		}
		if password != "" {
			if err := e.setLinuxPassword(ctx, linuxUsername, password); err != nil {
				return err
			}
		}
		return nil

	case "db_create_mariadb":
		return e.handleMariaDBCreate(ctx, t)

	case "db_delete_mariadb":
		return e.handleMariaDBDelete(ctx, t)

	case "db_create_postgres":
		return e.handlePostgresCreate(ctx, t)

	case "db_delete_postgres":
		return e.handlePostgresDelete(ctx, t)

	case "site_create":
		linuxUsername := strings.TrimSpace(t.Args["linux_username"])
		domain := strings.TrimSpace(t.Args["domain"])
		if linuxUsername == "" || domain == "" {
			return errors.New("linux_username and domain are required")
		}
		if err := validate.ValidateLinuxUsername(linuxUsername); err != nil {
			return err
		}
		normDomain, err := validate.NormalizeDomain(domain)
		if err != nil {
			return err
		}
		domain = normDomain

		root := filepath.Join("/home", linuxUsername, "web", domain, "public_html")
		if e.cfg.DryRun {
			log.Printf("[dry-run] site_create user=%s domain=%s root=%s", linuxUsername, domain, root)
			return nil
		}
		if err := e.ensureLinuxUser(ctx, linuxUsername); err != nil {
			return err
		}
		if err := e.ensurePHPFPM(ctx, linuxUsername); err != nil {
			return err
		}
		if err := os.MkdirAll(root, 0o755); err != nil {
			return err
		}
		_ = os.MkdirAll(filepath.Join("/home", linuxUsername, "web", domain, "logs"), 0o755)
		_ = e.runCommand(ctx, "chown", "-R", linuxUsername+":"+linuxUsername, filepath.Join("/home", linuxUsername, "web", domain))
		indexPath := filepath.Join(root, "index.php")
		if _, err := os.Stat(indexPath); errors.Is(err, os.ErrNotExist) {
			_ = os.WriteFile(indexPath, []byte("<?php echo 'Nebula Panel site ready';"), 0o644)
		}
		if err := e.writeNginxSiteConfig(domain, linuxUsername, false); err != nil {
			return err
		}
		if err := e.runCommand(ctx, "nginx", "-t"); err != nil {
			return err
		}
		if err := e.reloadService(ctx, "nginx"); err != nil {
			return err
		}
		return nil

	case "site_delete":
		linuxUsername := strings.TrimSpace(t.Args["linux_username"])
		domain := strings.TrimSpace(t.Args["domain"])
		if linuxUsername == "" || domain == "" {
			return errors.New("linux_username and domain are required")
		}
		if err := validate.ValidateLinuxUsername(linuxUsername); err != nil {
			return err
		}
		normDomain, err := validate.NormalizeDomain(domain)
		if err != nil {
			return err
		}
		domain = normDomain
		if e.cfg.DryRun {
			log.Printf("[dry-run] site_delete user=%s domain=%s", linuxUsername, domain)
			return nil
		}
		_ = e.disableNginxSite(domain)
		if err := e.runCommand(ctx, "nginx", "-t"); err != nil {
			return err
		}
		if err := e.reloadService(ctx, "nginx"); err != nil {
			return err
		}
		_ = os.RemoveAll(filepath.Join("/home", linuxUsername, "web", domain))
		return nil

	case "ssl_issue", "ssl_renew":
		return e.handleSSL(ctx, t)

	case "dns_apply":
		return e.handleDNSApply(ctx, t)

	case "dns_delete":
		return e.handleDNSDelete(ctx, t)

	case "mail_apply":
		return e.handleMailApply(ctx, t)

	case "backup_run", "backup_restore":
		if e.cfg.DryRun {
			log.Printf("[dry-run] %s target=%s", t.Type, t.Target)
		}
		return nil

	case "service_reload":
		svc := t.Args["service"]
		if svc == "" {
			return errors.New("service is required")
		}
		return e.reloadService(ctx, svc)
	}
	return nil
}

func (e *Executor) handleSSL(ctx context.Context, t Task) error {
	linuxUsername := strings.TrimSpace(t.Args["linux_username"])
	domain := strings.TrimSpace(t.Args["domain"])
	if domain == "" {
		return errors.New("domain is required")
	}
	if linuxUsername == "" {
		return errors.New("linux_username is required for SSL install")
	}
	if err := validate.ValidateLinuxUsername(linuxUsername); err != nil {
		return err
	}
	normDomain, err := validate.NormalizeDomain(domain)
	if err != nil {
		return err
	}
	domain = normDomain
	email := strings.TrimSpace(t.Args["email"])
	if email == "" {
		email = e.cfg.ACMEEmail
	}
	provider := strings.ToLower(strings.TrimSpace(t.Args["provider"]))
	if provider == "" {
		provider = "letsencrypt"
	}

	if err := os.MkdirAll(e.cfg.ACMEWebroot, 0o755); err != nil {
		return err
	}

	args := []string{
		"certonly",
		"--non-interactive",
		"--agree-tos",
		"--webroot",
		"-w", e.cfg.ACMEWebroot,
		"-d", domain,
		"--cert-name", domain,
		"--email", email,
		"--keep-until-expiring",
	}
	if provider == "zerossl" {
		args = append(args, "--server", "https://acme.zerossl.com/v2/DV90")
		if e.cfg.ZeroSSLEABKID != "" && e.cfg.ZeroSSLEABHMACKey != "" {
			args = append(args,
				"--eab-kid", e.cfg.ZeroSSLEABKID,
				"--eab-hmac-key", e.cfg.ZeroSSLEABHMACKey,
			)
		}
	}

	if err := e.runCommand(ctx, "certbot", args...); err != nil {
		return fmt.Errorf("%s certificate flow failed: %w", provider, err)
	}

	if !e.cfg.DryRun {
		if err := e.writeNginxSiteConfig(domain, linuxUsername, true); err != nil {
			return err
		}
		if err := e.runCommand(ctx, "nginx", "-t"); err != nil {
			return err
		}
	}

	_ = e.reloadService(ctx, "nginx")
	_ = e.reloadService(ctx, "postfix")
	_ = e.reloadService(ctx, "dovecot")
	return nil
}

func (e *Executor) handleDNSApply(ctx context.Context, t Task) error {
	if e.cfg.PowerDNSAPIKey == "" {
		return errors.New("PowerDNS API key is not configured")
	}
	zone := strings.TrimSpace(t.Args["zone"])
	if zone == "" {
		zone = strings.TrimSpace(t.Target)
	}
	if zone == "" {
		return errors.New("zone is required")
	}
	var records []dnsRecord
	if raw := t.Args["records_json"]; strings.TrimSpace(raw) != "" {
		if err := json.Unmarshal([]byte(raw), &records); err != nil {
			return fmt.Errorf("invalid records_json: %w", err)
		}
	}

	if e.cfg.DryRun {
		log.Printf("[dry-run] dns_apply zone=%s records=%d", zone, len(records))
		return nil
	}
	return e.applyPowerDNS(ctx, zone, records)
}

func (e *Executor) handleDNSDelete(ctx context.Context, t Task) error {
	if e.cfg.PowerDNSAPIKey == "" {
		return errors.New("PowerDNS API key is not configured")
	}
	zone := strings.TrimSpace(t.Args["zone"])
	if zone == "" {
		zone = strings.TrimSpace(t.Target)
	}
	if zone == "" {
		return errors.New("zone is required")
	}

	if e.cfg.DryRun {
		log.Printf("[dry-run] dns_delete zone=%s", zone)
		return nil
	}
	return e.deletePowerDNSZone(ctx, zone)
}

func (e *Executor) applyPowerDNS(ctx context.Context, zone string, records []dnsRecord) error {
	zoneName := ensureFQDN(zone)
	desired := buildDesiredRRsets(zoneName, records)

	existing, statusCode, err := e.getZone(ctx, zoneName)
	if err != nil && statusCode != http.StatusNotFound {
		return err
	}
	if statusCode == http.StatusNotFound {
		return e.createZone(ctx, zoneName, desired)
	}

	patch := buildPatchRRsets(existing.RRsets, desired)
	if len(patch) == 0 {
		return nil
	}

	payload := map[string]any{"rrsets": patch}
	body, _ := json.Marshal(payload)
	urlPath := e.pdnsZoneURL(zoneName)
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, urlPath, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("X-API-Key", e.cfg.PowerDNSAPIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("pdns patch failed status=%d body=%s", resp.StatusCode, string(raw))
	}
	return nil
}

func (e *Executor) deletePowerDNSZone(ctx context.Context, zone string) error {
	zoneName := ensureFQDN(zone)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, e.pdnsZoneURL(zoneName), nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-API-Key", e.cfg.PowerDNSAPIKey)
	resp, err := e.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("pdns delete zone failed status=%d body=%s", resp.StatusCode, string(raw))
	}
	return nil
}

func (e *Executor) getZone(ctx context.Context, zoneName string) (pdnsZoneResponse, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.pdnsZoneURL(zoneName), nil)
	if err != nil {
		return pdnsZoneResponse{}, 0, err
	}
	req.Header.Set("X-API-Key", e.cfg.PowerDNSAPIKey)
	resp, err := e.httpClient.Do(req)
	if err != nil {
		return pdnsZoneResponse{}, 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return pdnsZoneResponse{}, resp.StatusCode, nil
	}
	if resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return pdnsZoneResponse{}, resp.StatusCode, fmt.Errorf("pdns get zone failed status=%d body=%s", resp.StatusCode, string(raw))
	}
	var z pdnsZoneResponse
	if err := json.NewDecoder(resp.Body).Decode(&z); err != nil {
		return pdnsZoneResponse{}, resp.StatusCode, err
	}
	return z, resp.StatusCode, nil
}

func (e *Executor) createZone(ctx context.Context, zoneName string, desired []pdnsRRset) error {
	nameservers := []string{"ns1." + zoneName, "ns2." + zoneName}
	for _, rr := range desired {
		if rr.Type != "NS" {
			continue
		}
		ns := make([]string, 0, len(rr.Records))
		for _, r := range rr.Records {
			ns = append(ns, ensureFQDN(r.Content))
		}
		if len(ns) > 0 {
			nameservers = ns
		}
	}

	createRRsets := make([]map[string]any, 0, len(desired))
	for _, rr := range desired {
		createRRsets = append(createRRsets, map[string]any{
			"name":    rr.Name,
			"type":    rr.Type,
			"ttl":     rr.TTL,
			"records": rr.Records,
		})
	}

	payload := map[string]any{
		"name":        zoneName,
		"kind":        "Native",
		"nameservers": nameservers,
		"rrsets":      createRRsets,
	}
	body, _ := json.Marshal(payload)
	endpoint := strings.TrimRight(e.cfg.PowerDNSAPIURL, "/") + "/api/v1/servers/" + url.PathEscape(e.cfg.PowerDNSServerID) + "/zones"
	if e.cfg.DryRun {
		log.Printf("[dry-run] create pdns zone=%s", zoneName)
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("X-API-Key", e.cfg.PowerDNSAPIKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("pdns create zone failed status=%d body=%s", resp.StatusCode, string(raw))
	}
	return nil
}

func (e *Executor) pdnsZoneURL(zoneName string) string {
	return strings.TrimRight(e.cfg.PowerDNSAPIURL, "/") + "/api/v1/servers/" + url.PathEscape(e.cfg.PowerDNSServerID) + "/zones/" + url.PathEscape(zoneName)
}

func buildDesiredRRsets(zoneName string, records []dnsRecord) []pdnsRRset {
	type agg struct {
		ttl     int
		records []pdnsRecord
	}
	bucket := map[string]*agg{}
	for _, rec := range records {
		rType := strings.ToUpper(strings.TrimSpace(rec.Type))
		if rType == "" {
			continue
		}
		rName := normalizeRecordName(zoneName, rec.Name)
		key := rName + "|" + rType
		if _, ok := bucket[key]; !ok {
			ttl := rec.TTL
			if ttl <= 0 {
				ttl = 3600
			}
			bucket[key] = &agg{ttl: ttl, records: make([]pdnsRecord, 0, 1)}
		}
		bucket[key].records = append(bucket[key].records, pdnsRecord{Content: normalizeRecordContent(rType, rec.Value, rec.Priority), Disabled: false})
	}

	keys := make([]string, 0, len(bucket))
	for k := range bucket {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make([]pdnsRRset, 0, len(keys))
	for _, k := range keys {
		parts := strings.SplitN(k, "|", 2)
		a := bucket[k]
		out = append(out, pdnsRRset{
			Name:    parts[0],
			Type:    parts[1],
			TTL:     uint32(a.ttl),
			Records: a.records,
		})
	}
	return out
}

func buildPatchRRsets(existing, desired []pdnsRRset) []pdnsRRset {
	key := func(rr pdnsRRset) string { return rr.Name + "|" + rr.Type }
	desiredMap := make(map[string]pdnsRRset, len(desired))
	for _, rr := range desired {
		rr.ChangeType = "REPLACE"
		desiredMap[key(rr)] = rr
	}
	patch := make([]pdnsRRset, 0, len(existing)+len(desired))
	for _, rr := range existing {
		if rr.Type == "SOA" {
			continue
		}
		k := key(rr)
		if _, ok := desiredMap[k]; !ok {
			rr.ChangeType = "DELETE"
			patch = append(patch, rr)
		}
	}
	for _, rr := range desiredMap {
		patch = append(patch, rr)
	}
	sort.Slice(patch, func(i, j int) bool {
		if patch[i].Name == patch[j].Name {
			return patch[i].Type < patch[j].Type
		}
		return patch[i].Name < patch[j].Name
	})
	return patch
}

func normalizeRecordName(zoneName, name string) string {
	n := strings.TrimSpace(name)
	zoneRoot := strings.TrimSuffix(zoneName, ".")
	if n == "" || n == "@" || strings.EqualFold(n, zoneRoot) {
		return zoneName
	}
	if strings.HasSuffix(n, ".") {
		return n
	}
	if strings.HasSuffix(strings.ToLower(n), "."+strings.ToLower(zoneRoot)) {
		return ensureFQDN(n)
	}
	return ensureFQDN(n + "." + zoneRoot)
}

func normalizeRecordContent(recordType, value string, priority int) string {
	v := strings.TrimSpace(value)
	if recordType == "TXT" {
		if !strings.HasPrefix(v, "\"") {
			v = "\"" + strings.ReplaceAll(v, "\"", "\\\"") + "\""
		}
		return v
	}
	if recordType == "MX" {
		if priority <= 0 {
			priority = 10
		}
		return fmt.Sprintf("%d %s", priority, ensureFQDN(v))
	}
	if recordType == "CNAME" || recordType == "NS" {
		return ensureFQDN(v)
	}
	return v
}

func ensureFQDN(name string) string {
	n := strings.TrimSpace(name)
	if n == "" {
		return n
	}
	if !strings.HasSuffix(n, ".") {
		return n + "."
	}
	return n
}

func (e *Executor) handleMailApply(ctx context.Context, t Task) error {
	var domains []mailDomain
	var mailboxes []mailMailbox
	var aliases []mailAlias

	if raw := strings.TrimSpace(t.Args["domains_json"]); raw != "" {
		if err := json.Unmarshal([]byte(raw), &domains); err != nil {
			return fmt.Errorf("invalid domains_json: %w", err)
		}
	}
	if raw := strings.TrimSpace(t.Args["mailboxes_json"]); raw != "" {
		if err := json.Unmarshal([]byte(raw), &mailboxes); err != nil {
			return fmt.Errorf("invalid mailboxes_json: %w", err)
		}
	}
	if raw := strings.TrimSpace(t.Args["aliases_json"]); raw != "" {
		if err := json.Unmarshal([]byte(raw), &aliases); err != nil {
			return fmt.Errorf("invalid aliases_json: %w", err)
		}
	}

	if e.cfg.DryRun {
		log.Printf("[dry-run] mail_apply domains=%d mailboxes=%d aliases=%d", len(domains), len(mailboxes), len(aliases))
		return nil
	}

	if err := os.MkdirAll(e.cfg.GeneratedConfigDir, 0o750); err != nil {
		return err
	}

	domainLines := make([]string, 0, len(domains))
	seenDomain := map[string]bool{}
	for _, d := range domains {
		dn := strings.ToLower(strings.TrimSpace(d.Domain))
		if dn == "" || seenDomain[dn] {
			continue
		}
		seenDomain[dn] = true
		domainLines = append(domainLines, dn)
	}
	sort.Strings(domainLines)

	mailboxMapLines := make([]string, 0, len(mailboxes))
	dovecotUserLines := make([]string, 0, len(mailboxes))
	for _, mb := range mailboxes {
		address := strings.ToLower(strings.TrimSpace(mb.Address))
		if address == "" {
			continue
		}
		localPart := strings.SplitN(address, "@", 2)[0]
		domain := strings.ToLower(strings.TrimSpace(mb.Domain))
		mailboxMapLines = append(mailboxMapLines, fmt.Sprintf("%s %s/%s/", address, domain, localPart))
		password := mb.Password
		if strings.TrimSpace(password) == "" {
			password = randomPlaceholderPassword()
		}
		dovecotUserLines = append(dovecotUserLines, fmt.Sprintf("%s:{PLAIN}%s::::::", address, password))
	}
	sort.Strings(mailboxMapLines)
	sort.Strings(dovecotUserLines)

	aliasLines := make([]string, 0, len(aliases))
	for _, a := range aliases {
		source := strings.ToLower(strings.TrimSpace(a.Source))
		destination := strings.ToLower(strings.TrimSpace(a.Destination))
		if source == "" || destination == "" {
			continue
		}
		aliasLines = append(aliasLines, fmt.Sprintf("%s %s", source, destination))
	}
	sort.Strings(aliasLines)

	if err := writeLinesFile("/etc/postfix/virtual_mailbox_domains", domainLines, 0o644); err != nil {
		return err
	}
	if err := writeLinesFile("/etc/postfix/virtual_mailbox_maps", mailboxMapLines, 0o640); err != nil {
		return err
	}
	if err := writeLinesFile("/etc/postfix/virtual_alias_maps", aliasLines, 0o640); err != nil {
		return err
	}
	if err := writeLinesFile("/etc/dovecot/nebula-users", dovecotUserLines, 0o640); err != nil {
		return err
	}

	snapshot := map[string]any{
		"domains":   domains,
		"mailboxes": mailboxes,
		"aliases":   aliases,
		"updated_at": time.Now().UTC().Format(time.RFC3339),
	}
	raw, _ := json.MarshalIndent(snapshot, "", "  ")
	if err := os.WriteFile(filepath.Join(e.cfg.GeneratedConfigDir, "mail-state.json"), raw, 0o640); err != nil {
		return err
	}

	if err := ensureMainCFDirectives("/etc/postfix/main.cf", []string{
		"virtual_mailbox_domains = hash:/etc/postfix/virtual_mailbox_domains",
		"virtual_mailbox_maps = hash:/etc/postfix/virtual_mailbox_maps",
		"virtual_alias_maps = hash:/etc/postfix/virtual_alias_maps",
	}); err != nil {
		return err
	}

	if err := e.runCommand(ctx, "postmap", "/etc/postfix/virtual_mailbox_domains"); err != nil {
		return err
	}
	if err := e.runCommand(ctx, "postmap", "/etc/postfix/virtual_mailbox_maps"); err != nil {
		return err
	}
	if err := e.runCommand(ctx, "postmap", "/etc/postfix/virtual_alias_maps"); err != nil {
		return err
	}

	if err := e.reloadService(ctx, "postfix"); err != nil {
		return err
	}
	return e.reloadService(ctx, "dovecot")
}

func writeLinesFile(path string, lines []string, mode os.FileMode) error {
	content := strings.Join(lines, "\n")
	if len(lines) > 0 {
		content += "\n"
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), mode)
}

func ensureMainCFDirectives(path string, directives []string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	content := string(raw)
	changed := false
	for _, directive := range directives {
		if !strings.Contains(content, directive) {
			content += "\n" + directive + "\n"
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return os.WriteFile(path, []byte(content), 0o644)
}

func randomPlaceholderPassword() string {
	return "tmp-" + strings.ToLower(strings.ReplaceAll(time.Now().UTC().Format("150405"), ":", ""))
}

func (e *Executor) runCommand(ctx context.Context, name string, args ...string) error {
	if e.cfg.DryRun {
		log.Printf("[dry-run] %s %s", name, strings.Join(args, " "))
		return nil
	}
	cmdCtx, cancel := context.WithTimeout(ctx, e.cfg.CmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(cmdCtx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("command failed: %s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (e *Executor) reloadService(ctx context.Context, service string) error {
	allowedServices := map[string]bool{
		"nginx":   true,
		"pdns":    true,
		"postfix": true,
		"dovecot": true,
	}
	if !allowedServices[service] {
		return fmt.Errorf("service reload not allowed: %s", service)
	}
	return e.runCommand(ctx, "systemctl", "reload", service)
}

func (e *Executor) runCommandWithInput(ctx context.Context, input []byte, name string, args ...string) error {
	if e.cfg.DryRun {
		log.Printf("[dry-run] %s %s <stdin %d bytes>", name, strings.Join(args, " "), len(input))
		return nil
	}
	cmdCtx, cancel := context.WithTimeout(ctx, e.cfg.CmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(cmdCtx, name, args...)
	cmd.Stdin = bytes.NewReader(input)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("command failed: %s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (e *Executor) commandSucceeds(ctx context.Context, name string, args ...string) (bool, string, error) {
	if e.cfg.DryRun {
		return true, "", nil
	}
	cmdCtx, cancel := context.WithTimeout(ctx, e.cfg.CmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(cmdCtx, name, args...)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return true, string(out), nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return false, string(out), nil
	}
	return false, string(out), err
}

func (e *Executor) ensureLinuxUser(ctx context.Context, linuxUsername string) error {
	if err := validate.ValidateLinuxUsername(linuxUsername); err != nil {
		return err
	}

	ok, _, err := e.commandSucceeds(ctx, "getent", "group", "nebula-sftp")
	if err != nil {
		return err
	}
	if !ok {
		// idempotent in practice; groupadd fails if it already exists.
		_ = e.runCommand(ctx, "groupadd", "--system", "nebula-sftp")
	}

	ok, _, err = e.commandSucceeds(ctx, "id", "-u", linuxUsername)
	if err != nil {
		return err
	}
	if !ok {
		if err := e.runCommand(ctx, "useradd",
			"--create-home",
			"--home-dir", filepath.Join("/home", linuxUsername),
			"--shell", "/usr/sbin/nologin",
			"--user-group",
			linuxUsername,
		); err != nil {
			return err
		}
	}

	// Ensure SFTP group membership and chroot-safe home ownership.
	_ = e.runCommand(ctx, "usermod", "-aG", "nebula-sftp", linuxUsername)

	home := filepath.Join("/home", linuxUsername)
	_ = e.runCommand(ctx, "chown", "root:root", home)
	_ = e.runCommand(ctx, "chmod", "0755", home)

	for _, sub := range []string{"web", "logs"} {
		p := filepath.Join(home, sub)
		_ = os.MkdirAll(p, 0o755)
		_ = e.runCommand(ctx, "chown", "-R", linuxUsername+":"+linuxUsername, p)
	}

	return nil
}

func (e *Executor) setLinuxPassword(ctx context.Context, linuxUsername, password string) error {
	if strings.ContainsAny(password, "\r\n") {
		return errors.New("password contains newline characters")
	}
	line := []byte(linuxUsername + ":" + password + "\n")
	return e.runCommandWithInput(ctx, line, "chpasswd")
}

func (e *Executor) detectPHPFPM() (phpVersion string, poolDir string, service string, err error) {
	entries, err := os.ReadDir("/etc/php")
	if err != nil {
		return "", "", "", err
	}
	type cand struct {
		ver        string
		majorMinor [2]int
	}
	cands := make([]cand, 0)
	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		ver := ent.Name()
		parts := strings.Split(ver, ".")
		if len(parts) < 2 {
			continue
		}
		maj, err1 := strconv.Atoi(parts[0])
		min, err2 := strconv.Atoi(parts[1])
		if err1 != nil || err2 != nil {
			continue
		}
		dir := filepath.Join("/etc/php", ver, "fpm", "pool.d")
		if _, err := os.Stat(dir); err == nil {
			cands = append(cands, cand{ver: ver, majorMinor: [2]int{maj, min}})
		}
	}
	if len(cands) == 0 {
		return "", "", "", errors.New("php-fpm not installed (missing /etc/php/*/fpm/pool.d)")
	}
	sort.Slice(cands, func(i, j int) bool {
		if cands[i].majorMinor[0] == cands[j].majorMinor[0] {
			return cands[i].majorMinor[1] > cands[j].majorMinor[1]
		}
		return cands[i].majorMinor[0] > cands[j].majorMinor[0]
	})
	phpVersion = cands[0].ver
	poolDir = filepath.Join("/etc/php", phpVersion, "fpm", "pool.d")
	service = "php" + phpVersion + "-fpm"
	return phpVersion, poolDir, service, nil
}

func (e *Executor) ensurePHPFPM(ctx context.Context, linuxUsername string) error {
	_, poolDir, svc, err := e.detectPHPFPM()
	if err != nil {
		return err
	}

	poolName := "nebula-" + linuxUsername
	socketPath := filepath.Join("/run/php", poolName+".sock")
	poolPath := filepath.Join(poolDir, poolName+".conf")

	cfg := fmt.Sprintf(`[%%s]
user = %s
group = %s

listen = %s
listen.owner = www-data
listen.group = www-data
listen.mode = 0660

pm = ondemand
pm.max_children = 10
pm.process_idle_timeout = 10s
pm.max_requests = 500

php_admin_flag[log_errors] = on
php_admin_value[error_log] = /home/%s/logs/php-fpm-error.log
`, linuxUsername, linuxUsername, socketPath, linuxUsername)
	cfg = fmt.Sprintf(cfg, poolName)

	if err := e.writeFileAtomic(poolPath, []byte(cfg), 0o644); err != nil {
		return err
	}
	// Reload PHP-FPM so the pool takes effect.
	if err := e.runCommand(ctx, "systemctl", "reload", svc); err != nil {
		// Some systems don't support reload; restart is safe here.
		if err := e.runCommand(ctx, "systemctl", "restart", svc); err != nil {
			return err
		}
	}
	return nil
}

func (e *Executor) nginxSiteName(domain string) string {
	return "nebula-site-" + domain + ".conf"
}

func (e *Executor) nginxAvailablePath(domain string) string {
	return filepath.Join("/etc/nginx/sites-available", e.nginxSiteName(domain))
}

func (e *Executor) nginxEnabledPath(domain string) string {
	return filepath.Join("/etc/nginx/sites-enabled", e.nginxSiteName(domain))
}

func (e *Executor) writeNginxSiteConfig(domain, linuxUsername string, tlsEnabled bool) error {
	if err := validate.ValidateLinuxUsername(linuxUsername); err != nil {
		return err
	}
	normDomain, err := validate.NormalizeDomain(domain)
	if err != nil {
		return err
	}
	domain = normDomain

	root := filepath.Join("/home", linuxUsername, "web", domain, "public_html")
	socket := filepath.Join("/run/php", "nebula-"+linuxUsername+".sock")
	acmeRoot := e.cfg.ACMEWebroot
	sitePath := e.nginxAvailablePath(domain)

	var conf string
	if !tlsEnabled {
		conf = fmt.Sprintf(`# Managed by Nebula Panel. Manual edits may be overwritten.
server {
    listen 80;
    listen [::]:80;
    server_name %s;

    root %s;
    index index.php index.html;

    location ^~ /.well-known/acme-challenge/ {
        root %s;
        default_type "text/plain";
    }

    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }

    location ~ \\.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:%s;
    }

    location ~ /\\. {
        deny all;
    }
}
`, domain, root, acmeRoot, socket)
	} else {
		cert := filepath.Join("/etc/letsencrypt/live", domain, "fullchain.pem")
		key := filepath.Join("/etc/letsencrypt/live", domain, "privkey.pem")
		conf = fmt.Sprintf(`# Managed by Nebula Panel. Manual edits may be overwritten.
server {
    listen 80;
    listen [::]:80;
    server_name %s;

    location ^~ /.well-known/acme-challenge/ {
        root %s;
        default_type "text/plain";
    }

    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name %s;

    ssl_certificate %s;
    ssl_certificate_key %s;
    ssl_protocols TLSv1.2 TLSv1.3;

    root %s;
    index index.php index.html;

    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }

    location ~ \\.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:%s;
    }

    location ~ /\\. {
        deny all;
    }
}
`, domain, acmeRoot, domain, cert, key, root, socket)
	}

	if err := e.writeFileAtomic(sitePath, []byte(conf), 0o644); err != nil {
		return err
	}

	// Enable site (idempotent).
	enabled := e.nginxEnabledPath(domain)
	_ = os.Remove(enabled)
	if err := os.Symlink(sitePath, enabled); err != nil {
		return err
	}
	return nil
}

func (e *Executor) disableNginxSite(domain string) error {
	normDomain, err := validate.NormalizeDomain(domain)
	if err != nil {
		return err
	}
	domain = normDomain
	_ = os.Remove(e.nginxEnabledPath(domain))
	_ = os.Remove(e.nginxAvailablePath(domain))
	return nil
}

func (e *Executor) writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func sqlQuoteLiteral(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

func (e *Executor) handleMariaDBCreate(ctx context.Context, t Task) error {
	dbName := strings.ToLower(strings.TrimSpace(t.Args["db_name"]))
	dbUser := strings.ToLower(strings.TrimSpace(t.Args["db_user"]))
	dbPass := strings.TrimSpace(t.Args["db_password"])
	if dbName == "" || dbUser == "" || dbPass == "" {
		return errors.New("db_name, db_user, and db_password are required")
	}
	if err := validate.ValidateDBIdentifier(dbName); err != nil {
		return err
	}
	if err := validate.ValidateDBIdentifier(dbUser); err != nil {
		return err
	}
	sql := fmt.Sprintf(
		"CREATE DATABASE IF NOT EXISTS `%s`;\n"+
			"CREATE USER IF NOT EXISTS '%s'@'localhost' IDENTIFIED BY '%s';\n"+
			"GRANT ALL PRIVILEGES ON `%s`.* TO '%s'@'localhost';\n"+
			"FLUSH PRIVILEGES;\n",
		dbName,
		dbUser,
		sqlQuoteLiteral(dbPass),
		dbName,
		dbUser,
	)
	return e.runCommand(ctx, "mysql", "-e", sql)
}

func (e *Executor) handleMariaDBDelete(ctx context.Context, t Task) error {
	dbName := strings.ToLower(strings.TrimSpace(t.Args["db_name"]))
	dbUser := strings.ToLower(strings.TrimSpace(t.Args["db_user"]))
	if dbName == "" || dbUser == "" {
		return errors.New("db_name and db_user are required")
	}
	if err := validate.ValidateDBIdentifier(dbName); err != nil {
		return err
	}
	if err := validate.ValidateDBIdentifier(dbUser); err != nil {
		return err
	}
	sql := fmt.Sprintf(
		"DROP DATABASE IF EXISTS `%s`;\n"+
			"DROP USER IF EXISTS '%s'@'localhost';\n"+
			"FLUSH PRIVILEGES;\n",
		dbName,
		dbUser,
	)
	return e.runCommand(ctx, "mysql", "-e", sql)
}

func (e *Executor) pgQuery(ctx context.Context, query string) (string, error) {
	ok, out, err := e.commandSucceeds(ctx, "runuser", "-u", "postgres", "--", "psql", "-tAc", query)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("psql query failed: %s", strings.TrimSpace(out))
	}
	return strings.TrimSpace(out), nil
}

func (e *Executor) handlePostgresCreate(ctx context.Context, t Task) error {
	dbName := strings.ToLower(strings.TrimSpace(t.Args["db_name"]))
	dbUser := strings.ToLower(strings.TrimSpace(t.Args["db_user"]))
	dbPass := strings.TrimSpace(t.Args["db_password"])
	if dbName == "" || dbUser == "" || dbPass == "" {
		return errors.New("db_name, db_user, and db_password are required")
	}
	if err := validate.ValidateDBIdentifier(dbName); err != nil {
		return err
	}
	if err := validate.ValidateDBIdentifier(dbUser); err != nil {
		return err
	}

	roleExists, err := e.pgQuery(ctx, fmt.Sprintf("SELECT 1 FROM pg_roles WHERE rolname='%s'", sqlQuoteLiteral(dbUser)))
	if err != nil {
		return err
	}
	if roleExists != "1" {
		if err := e.runCommand(ctx, "runuser", "-u", "postgres", "--", "psql", "-v", "ON_ERROR_STOP=1", "-c",
			fmt.Sprintf("CREATE ROLE %s WITH LOGIN PASSWORD '%s';", dbUser, sqlQuoteLiteral(dbPass)),
		); err != nil {
			return err
		}
	}

	dbExists, err := e.pgQuery(ctx, fmt.Sprintf("SELECT 1 FROM pg_database WHERE datname='%s'", sqlQuoteLiteral(dbName)))
	if err != nil {
		return err
	}
	if dbExists != "1" {
		if err := e.runCommand(ctx, "runuser", "-u", "postgres", "--", "psql", "-v", "ON_ERROR_STOP=1", "-c",
			fmt.Sprintf("CREATE DATABASE %s OWNER %s;", dbName, dbUser),
		); err != nil {
			return err
		}
	}
	return nil
}

func (e *Executor) handlePostgresDelete(ctx context.Context, t Task) error {
	dbName := strings.ToLower(strings.TrimSpace(t.Args["db_name"]))
	dbUser := strings.ToLower(strings.TrimSpace(t.Args["db_user"]))
	if dbName == "" || dbUser == "" {
		return errors.New("db_name and db_user are required")
	}
	if err := validate.ValidateDBIdentifier(dbName); err != nil {
		return err
	}
	if err := validate.ValidateDBIdentifier(dbUser); err != nil {
		return err
	}
	if err := e.runCommand(ctx, "runuser", "-u", "postgres", "--", "psql", "-v", "ON_ERROR_STOP=1", "-c",
		fmt.Sprintf("DROP DATABASE IF EXISTS %s;", dbName),
	); err != nil {
		return err
	}
	if err := e.runCommand(ctx, "runuser", "-u", "postgres", "--", "psql", "-v", "ON_ERROR_STOP=1", "-c",
		fmt.Sprintf("DROP ROLE IF EXISTS %s;", dbUser),
	); err != nil {
		return err
	}
	return nil
}
