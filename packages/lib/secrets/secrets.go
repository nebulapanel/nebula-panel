package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	prefixV1 = "enc:v1:"
)

// KeyBytes parses NEBULA_APP_KEY into a 32-byte key.
//
// Supported formats:
// - base64 (standard or raw URL)
// - hex
// - raw string of 32 bytes
func KeyBytes(appKey string) ([]byte, error) {
	k := strings.TrimSpace(appKey)
	if k == "" {
		return nil, errors.New("app key is empty")
	}

	// Try hex.
	if b, err := hex.DecodeString(k); err == nil {
		if len(b) != 32 {
			return nil, fmt.Errorf("hex key must decode to 32 bytes, got %d", len(b))
		}
		return b, nil
	}

	// Try base64 (Std + RawURLEncoding).
	if b, err := base64.StdEncoding.DecodeString(k); err == nil {
		if len(b) != 32 {
			return nil, fmt.Errorf("base64 key must decode to 32 bytes, got %d", len(b))
		}
		return b, nil
	}
	if b, err := base64.RawURLEncoding.DecodeString(k); err == nil {
		if len(b) != 32 {
			return nil, fmt.Errorf("base64url key must decode to 32 bytes, got %d", len(b))
		}
		return b, nil
	}

	// Raw bytes.
	if len(k) == 32 {
		return []byte(k), nil
	}
	return nil, errors.New("unsupported app key format; provide 32-byte hex or base64")
}

func Encrypt(appKey string, plaintext string) (string, error) {
	key, err := KeyBytes(appKey)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nil, nonce, []byte(plaintext), nil)

	buf := make([]byte, 0, len(nonce)+len(ct))
	buf = append(buf, nonce...)
	buf = append(buf, ct...)
	return prefixV1 + base64.RawURLEncoding.EncodeToString(buf), nil
}

func Decrypt(appKey string, encoded string) (string, error) {
	key, err := KeyBytes(appKey)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	raw := strings.TrimSpace(encoded)
	if !strings.HasPrefix(raw, prefixV1) {
		return "", errors.New("not an encrypted secret")
	}
	raw = strings.TrimPrefix(raw, prefixV1)

	buf, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return "", err
	}
	if len(buf) < gcm.NonceSize() {
		return "", errors.New("encrypted secret too short")
	}
	nonce := buf[:gcm.NonceSize()]
	ct := buf[gcm.NonceSize():]
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// EncryptOrBase64 encrypts when appKey is configured, otherwise it falls back to
// base64 (legacy behavior). Prefer setting NEBULA_APP_KEY in production.
func EncryptOrBase64(appKey string, plaintext string) string {
	enc, err := Encrypt(appKey, plaintext)
	if err == nil {
		return enc
	}
	return base64.StdEncoding.EncodeToString([]byte(plaintext))
}

// DecryptAuto decrypts secrets produced by EncryptOrBase64.
func DecryptAuto(appKey string, encoded string) (string, error) {
	raw := strings.TrimSpace(encoded)
	if strings.HasPrefix(raw, prefixV1) {
		return Decrypt(appKey, raw)
	}
	b, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

