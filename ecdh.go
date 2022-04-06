package goxchange

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"hash"
	"math/big"
)

type PrivateKey struct {
	*ecdsa.PrivateKey
}

func newKey() *PrivateKey {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil
	}
	return &PrivateKey{key}
}

func (k *PrivateKey) MarshalPublic() []byte {
	var data bytes.Buffer
	data.Write(k.PublicKey.X.Bytes())
	data.Write(k.PublicKey.Y.Bytes())
	return data.Bytes()
}

func (k *PrivateKey) UnmarshalPublic(data []byte) ecdsa.PublicKey {
	return ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(data[:32]),
		Y:     new(big.Int).SetBytes(data[32:]),
	}
}

func (k *PrivateKey) sharedSecret(P ecdsa.PublicKey) []byte {
	x, _ := P.ScalarMult(P.X, P.Y, k.D.Bytes())
	return pbkdf(x.Bytes(), []byte("goxchange"), 4096, 32, sha256.New)
}

func pbkdf(password, salt []byte, iter, keyLen int, h func() hash.Hash) []byte {
	prf := hmac.New(h, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen

	var buf [4]byte
	dk := make([]byte, 0, numBlocks*hashLen)
	U := make([]byte, hashLen)
	for block := 1; block <= numBlocks; block++ {
		// N.B.: || means concatenation, ^ means XOR
		// for each block T_i = U_1 ^ U_2 ^ ... ^ U_iter
		// U_1 = PRF(password, salt || uint(i))
		prf.Reset()
		prf.Write(salt)
		buf[0] = byte(block >> 24)
		buf[1] = byte(block >> 16)
		buf[2] = byte(block >> 8)
		buf[3] = byte(block)
		prf.Write(buf[:4])
		dk = prf.Sum(dk)
		T := dk[len(dk)-hashLen:]
		copy(U, T)

		// U_n = PRF(password, U_(n-1))
		for n := 2; n <= iter; n++ {
			prf.Reset()
			prf.Write(U)
			U = U[:0]
			U = prf.Sum(U)
			for x := range U {
				T[x] ^= U[x]
			}
		}
	}
	return dk[:keyLen]
}
