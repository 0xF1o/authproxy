package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
)

var (
	pinHash  string
	target   *url.URL
	proxy    *httputil.ReverseProxy
	salt     [16]byte
	cookieNm string
)

const listenAddr = ":8473"

func hashPin(pin string) string {
	sum := sha256.Sum256(append(append(make([]byte, 0, 16+len(pin)), salt[:]...), []byte(pin)...))
	return hex.EncodeToString(sum[:])
}

//go:embed login.html
var loginPage string

func main() {
	pin := os.Getenv("AUTH_PIN")
	if pin == "" {
		log.Fatal("AUTH_PIN environment variable must be set")
	}
	rand.Read(salt[:])
	pinHash = hashPin(pin)
	initCrypto()
	cookieNm = os.Getenv("COOKIE_NAME")
	if cookieNm == "" {
		cookieNm = "auth_pin"
	}
	var err error
	if target, err = url.Parse(os.Getenv("TARGET")); err != nil || target.Scheme == "" || target.Host == "" {
		log.Fatal("TARGET must be a valid http(s) URL")
	}
	proxy = newReverseProxy()
	mux := http.NewServeMux()
	mux.HandleFunc("/", auth)
	log.Printf("authproxy listening on %s, forwarding to %s", listenAddr, target)
	if err := http.ListenAndServe(listenAddr, mux); err != nil {
		log.Fatal(err)
	}
}

func auth(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		login(w, r)
		return
	}
	if c, err := r.Cookie(cookieNm); err == nil && subtle.ConstantTimeCompare([]byte(c.Value), []byte(pinHash)) == 1 {
		proxy.ServeHTTP(w, r)
		return
	}
	reply(w, r, http.StatusOK, "")
}

func login(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		reply(w, r, http.StatusBadRequest, "Invalid request.")
		return
	}
	c, err := decryptPin(r.FormValue("pin_enc"))
	if err != nil {
		reply(w, r, http.StatusBadRequest, "Encryption key expired, please reload.")
		return
	}
	if !nonceValid(c.N) {
		reply(w, r, http.StatusBadRequest, "Login expired, please reload.")
		return
	}
	if subtle.ConstantTimeCompare([]byte(hashPin(c.Pin)), []byte(pinHash)) != 1 {
		reply(w, r, http.StatusUnauthorized, "Invalid pin. Please try again.")
		return
	}
	redeemNonce(c.N)
	setCookie(w)
	if wantsJSON(r) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}
	http.Redirect(w, r, target.Path, http.StatusFound)
}

func reply(w http.ResponseWriter, r *http.Request, code int, errMsg string) {
	w.Header().Set("Cache-Control", "no-store")
	if wantsJSON(r) {
		writeJSON(w, code, map[string]any{"ok": false, "error": errMsg})
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK) // 200 so browsers render the form, not their own error page
	w.Write([]byte(renderLogin(errMsg)))
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func wantsJSON(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "application/json")
}

func renderLogin(errMsg string) string {
	return strings.NewReplacer("__ERROR__", errMsg, "__PUBKEY__", pubJWK, "__NONCE__", issueNonce()).Replace(loginPage)
}

func setCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: cookieNm, Value: pinHash, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode})
}

func newReverseProxy() *httputil.ReverseProxy {
	p := httputil.NewSingleHostReverseProxy(target)
	p.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, err error) {
		log.Printf("upstream error: %v", err)
		http.Error(w, "bad gateway", http.StatusBadGateway)
	}
	return p
}
