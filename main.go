package main

import (
	_ "embed"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
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
		r.ParseForm()
		if subtle.ConstantTimeCompare([]byte(hashPin(r.FormValue("pin"))), []byte(pinHash)) == 1 {
			setCookie(w)
			loc := r.URL.EscapedPath()
			if r.URL.RawQuery != "" { loc += "?" + r.URL.RawQuery }
			http.Redirect(w, r, loc, http.StatusFound)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(renderLogin("Invalid pin. Please try again.")))
		return
	}
	if c, err := r.Cookie(cookieNm); err == nil && subtle.ConstantTimeCompare([]byte(c.Value), []byte(pinHash)) == 1 {
		proxy.ServeHTTP(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(renderLogin("")))
}

func renderLogin(errMsg string) string {
	return strings.Replace(loginPage, "__ERROR__", errMsg, 1)
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
