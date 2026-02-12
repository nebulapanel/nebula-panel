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
	"strings"
	"time"

	"github.com/nebula-panel/nebula/apps/agent/internal/config"
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
			"site_create":    true,
			"site_delete":    true,
			"ssl_issue":      true,
			"ssl_renew":      true,
			"dns_apply":      true,
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
	case "site_create":
		owner := strings.TrimSpace(t.Args["owner_id"])
		domain := strings.TrimSpace(t.Args["domain"])
		if owner == "" || domain == "" {
			return errors.New("owner_id and domain are required")
		}
		root := filepath.Join("/home", owner, "web", domain, "public_html")
		if e.cfg.DryRun {
			log.Printf("[dry-run] mkdir -p %s", root)
			return nil
		}
		if err := os.MkdirAll(root, 0o750); err != nil {
			return err
		}
		indexPath := filepath.Join(root, "index.php")
		if _, err := os.Stat(indexPath); errors.Is(err, os.ErrNotExist) {
			_ = os.WriteFile(indexPath, []byte("<?php echo 'Nebula Panel site ready';"), 0o640)
		}
		return nil

	case "site_delete":
		if e.cfg.DryRun {
			log.Printf("[dry-run] site_delete target=%s", t.Target)
		}
		return nil

	case "ssl_issue", "ssl_renew":
		return e.handleSSL(ctx, t)

	case "dns_apply":
		return e.handleDNSApply(ctx, t)

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
	domain := strings.TrimSpace(t.Args["domain"])
	if domain == "" {
		return errors.New("domain is required")
	}
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
	if n == "" || n == "@" {
		return zoneName
	}
	if strings.HasSuffix(n, ".") {
		return n
	}
	if strings.HasSuffix(strings.ToLower(n), strings.ToLower(zoneName)) {
		return ensureFQDN(n)
	}
	return ensureFQDN(n + "." + strings.TrimSuffix(zoneName, "."))
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
