package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

func VerifyHMAC(payload []byte, providedHex, secret string) bool {
	expected := SignHMAC(payload, secret)
	return hmac.Equal([]byte(expected), []byte(providedHex))
}

func SignHMAC(payload []byte, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write(payload)
	return hex.EncodeToString(h.Sum(nil))
}
