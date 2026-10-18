package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// setup resets the package globals for a test; up may be nil (then target is a closed port).
func setup(t *testing.T, pin string, up *httptest.Server) {
	t.Helper()
	salt = [16]byte{}
	pinHash = hashPin(pin)
	cookieNm = "auth_pin"
	u := "http://127.0.0.1:1"
	if up != nil { u = up.URL }
	target, _ = url.Parse(u)
	proxy = newReverseProxy()
}

func newPost(t *testing.T, uri, pin string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, uri, strings.NewReader("pin="+pin))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

func TestLoginSuccess(t *testing.T) {
	setup(t, "1234", nil)
	w := httptest.NewRecorder()
	auth(w, newPost(t, "/1/2/3/4?x=1&y=2", "1234"))
	if w.Code != http.StatusFound { t.Fatalf("code = %d", w.Code) }
	if loc := w.Header().Get("Location"); loc != "/1/2/3/4?x=1&y=2" { t.Errorf("Location = %q", loc) }
	cs := w.Result().Cookies()
	if len(cs) != 1 { t.Fatalf("cookies = %v", cs) }
	c := cs[0]
	if c.Name != "auth_pin" || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode { t.Errorf("cookie = %+v", c) }
	if c.Value != pinHash || c.Value == "1234" { t.Errorf("cookie value must be the pin hash, got %q", c.Value) }
}

func TestLoginFailure(t *testing.T) {
	setup(t, "1234", nil)
	for _, pin := range []string{"9999", ""} {
		w := httptest.NewRecorder()
		auth(w, newPost(t, "/1/2/3/4", pin))
		if w.Code != http.StatusOK { t.Fatalf("pin=%q code = %d", pin, w.Code) }
		if cc := w.Header().Get("Cache-Control"); cc != "no-store" { t.Errorf("pin=%q Cache-Control = %q", pin, cc) }
		if body := w.Body.String(); !strings.Contains(body, "Invalid pin") || strings.Contains(body, "__ERROR__") { t.Errorf("pin=%q body = %q", pin, body) }
		if len(w.Result().Cookies()) != 0 { t.Errorf("pin=%q set a cookie on failure", pin) }
	}
}

func TestAuthenticatedProxy(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "upstream: "+r.URL.RequestURI()) }))
	defer up.Close()
	setup(t, "1234", up)
	r := httptest.NewRequest(http.MethodGet, "/1/2/3/4?x=1", nil)
	r.AddCookie(&http.Cookie{Name: "auth_pin", Value: pinHash})
	w := httptest.NewRecorder()
	auth(w, r)
	if w.Code != http.StatusOK || w.Body.String() != "upstream: /1/2/3/4?x=1" { t.Fatalf("code=%d body=%q", w.Code, w.Body.String()) }
}

func TestUnauthenticatedShowsLogin(t *testing.T) {
	setup(t, "1234", nil)
	for _, val := range []string{"", "1234", "deadbeef"} {
		r := httptest.NewRequest(http.MethodGet, "/1/2/3/4", nil)
		if val != "" { r.AddCookie(&http.Cookie{Name: "auth_pin", Value: val}) }
		w := httptest.NewRecorder()
		auth(w, r)
		if w.Code != http.StatusOK { t.Fatalf("val=%q code = %d", val, w.Code) }
		if cc := w.Header().Get("Cache-Control"); cc != "no-store" { t.Errorf("val=%q Cache-Control = %q", val, cc) }
		if body := w.Body.String(); !strings.Contains(body, "Pin required") || strings.Contains(body, "__ERROR__") { t.Errorf("val=%q body = %q", val, body) }
	}
}

func TestUpstreamError(t *testing.T) {
	setup(t, "1234", nil) // target is a closed port
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: "auth_pin", Value: pinHash})
	w := httptest.NewRecorder()
	auth(w, r)
	if w.Code != http.StatusBadGateway { t.Fatalf("code = %d", w.Code) }
}

func TestHashPin(t *testing.T) {
	salt = [16]byte{7}
	a := hashPin("1234")
	if a != hashPin("1234") { t.Error("not deterministic") }
	if a == hashPin("1235") { t.Error("different pins collide") }
	salt[0] = 8
	if a == hashPin("1234") { t.Error("salt has no effect") }
}

func TestRenderLogin(t *testing.T) {
	if got := renderLogin("boom"); !strings.Contains(got, "boom") || strings.Contains(got, "__ERROR__") { t.Errorf("got = %q", got) }
	if strings.Contains(renderLogin(""), "__ERROR__") { t.Error("placeholder not replaced") }
}
