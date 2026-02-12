package tasks

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

type Client struct {
	hc     *http.Client
	secret string
}

type Request struct {
	Type      string            `json:"type"`
	Target    string            `json:"target"`
	Args      map[string]string `json:"args"`
	Timestamp time.Time         `json:"timestamp"`
}

func New(socketPath, secret string) *Client {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
		},
	}
	return &Client{
		hc: &http.Client{
			Timeout:   6 * time.Second,
			Transport: transport,
		},
		secret: secret,
	}
}

func (c *Client) Submit(ctx context.Context, req Request) error {
	req.Timestamp = time.Now().UTC()
	b, err := json.Marshal(req)
	if err != nil {
		return err
	}
	h := hmac.New(sha256.New, []byte(c.secret))
	h.Write(b)
	sig := hex.EncodeToString(h.Sum(nil))

	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/v1/tasks", bytes.NewReader(b))
	if err != nil {
		return err
	}
	hreq.Header.Set("Content-Type", "application/json")
	hreq.Header.Set("X-Nebula-Signature", sig)

	resp, err := c.hc.Do(hreq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("task rejected: %s", string(raw))
	}
	return nil
}
