package goxchange

import (
	"crypto/rand"

	"golang.org/x/crypto/chacha20poly1305"
)

func Encrypt(plaintext []byte, Key []byte) ([]byte, error) {
	cipher, err := chacha20poly1305.NewX(Key)
	if err != nil {
		return nil, err
	}
	var nonce = make([]byte, chacha20poly1305.NonceSizeX)
	rand.Read(nonce)
	nonce = append(nonce, cipher.Seal(nil, nonce, plaintext, nil)...)
	return nonce, nil
}

func Decrypt(ciphertext []byte, Key []byte) ([]byte, error) {
	cipher, err := chacha20poly1305.NewX(Key)
	if err != nil {
		return nil, err
	}
	nonce := ciphertext[:chacha20poly1305.NonceSizeX]
	plaintext, err := cipher.Open(nil, nonce, ciphertext[chacha20poly1305.NonceSizeX:], nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
