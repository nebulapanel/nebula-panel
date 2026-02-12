package security

import "testing"

func TestSignVerify(t *testing.T) {
	payload := []byte("hello")
	secret := "abc"
	sig := SignHMAC(payload, secret)
	if !VerifyHMAC(payload, sig, secret) {
		t.Fatalf("expected signature to verify")
	}
	if VerifyHMAC(payload, sig, "wrong") {
		t.Fatalf("expected signature to fail with wrong secret")
	}
}
