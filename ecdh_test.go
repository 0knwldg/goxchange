package goxchange

import (
	"bytes"
	"testing"
)

func TestSharedSecret(t *testing.T) {
	bob := newKey()
	if bob.PrivateKey == nil {
		t.Fatalf("Unable to generate private key")
	}
	alice := newKey()
	if alice.PrivateKey == nil {
		t.Fatalf("Unable to generate private key")
	}
	sharedBob := bob.sharedSecret(alice.PublicKey)
	sharedAlice := alice.sharedSecret(bob.PublicKey)
	if bytes.EqualFold(sharedBob, sharedAlice) == false {
		t.Fatalf("Shared secret mismatch")
	}
}

func TestMarshal(t *testing.T) {
	bob := newKey()
	data := bob.MarshalPublic()
	pub := bob.UnmarshalPublic(data)
	if bytes.EqualFold(bob.PublicKey.X.Bytes(), pub.X.Bytes()) == false {
		t.Fatalf("Bytes mismatch")
	}
	if bytes.EqualFold(bob.PublicKey.Y.Bytes(), pub.Y.Bytes()) == false {
		t.Fatalf("Bytes mismatch")
	}
}
