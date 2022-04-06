package goxchange

import (
	"bytes"
	"testing"
)

func TestEncrypt(t *testing.T) {
	plaintext := []byte("Hello World")
	key := bytes.Repeat([]byte{0x41}, 32)
	ciphertext, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Unable to encrypt: %s", err)
	}
	plaintext2, err := Decrypt(ciphertext, key)
	if err != nil {
		t.Fatalf("Unable to decrypt: %s", err)
	}
	if bytes.EqualFold(plaintext, plaintext2) == false {
		t.Fatalf("Plaintext mismatch")
	}
}
