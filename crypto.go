package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log"
	"math/big"
	"sync"
	"time"
)

// privKey decrypts the pin submitted by the browser. It is generated fresh on
// every start, so a passive eavesdropper who records a ciphertext cannot
// decrypt it after a restart.
var (
	privKey *rsa.PrivateKey
	pubJWK  string
)

func initCrypto() {
	var err error
	if privKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		log.Fatal(err)
	}
	pubJWK = publicJWK(&privKey.PublicKey)
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func publicJWK(pub *rsa.PublicKey) string {
	jwk := map[string]string{"kty": "RSA", "n": b64u(pub.N.Bytes()), "e": b64u(big.NewInt(int64(pub.E)).Bytes()), "alg": "RSA-OAEP-256"}
	js, _ := json.Marshal(jwk)
	return string(js)
}

type creds struct {
	N   string `json:"n"` // single-use nonce from the login page
	Pin string `json:"pin"`
}

func decryptPin(enc string) (creds, error) {
	var c creds
	ct, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		return c, err
	}
	plain, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, ct, nil)
	if err != nil {
		return c, err
	}
	err = json.Unmarshal(plain, &c)
	return c, err
}

// nonceStore hands out single-use, short-lived nonces so a captured ciphertext
// cannot simply be replayed (unlike a password, ciphertext is always accepted).
var (
	nonceMu    sync.Mutex
	nonceMap   = map[string]time.Time{}
	nonceTTL   = 5 * time.Minute
	nonceLimit = 1024
)

func issueNonce() string {
	b := make([]byte, 16)
	rand.Read(b)
	n := hex.EncodeToString(b)
	now := time.Now()
	nonceMu.Lock()
	defer nonceMu.Unlock()
	for k, exp := range nonceMap {
		if now.After(exp) {
			delete(nonceMap, k)
		}
	}
	if len(nonceMap) >= nonceLimit {
		nonceMap = map[string]time.Time{}
	}
	nonceMap[n] = now.Add(nonceTTL)
	return n
}

func nonceValid(n string) bool {
	nonceMu.Lock()
	defer nonceMu.Unlock()
	exp, ok := nonceMap[n]
	return ok && time.Now().Before(exp)
}

// redeemNonce burns a nonce so its ciphertext cannot be replayed.
func redeemNonce(n string) {
	nonceMu.Lock()
	defer nonceMu.Unlock()
	delete(nonceMap, n)
}
