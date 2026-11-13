package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/collegeming/cpa-jethub-plugins/internal/abiboot"
)

// doImpersonated reaches a local TLS server through a local HTTP CONNECT
// proxy, using the utls Chrome fingerprint. The host HTTPDo path is not
// involved.
func TestImpersonatedDoThroughHTTPProxy(t *testing.T) {
	var hits atomic.Int32
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("User-Agent") != AccountUA {
			t.Errorf("upstream UA = %q, want official client UA", r.Header.Get("User-Agent"))
		}
		if r.URL.Path != "/points/records" {
			t.Errorf("path = %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"code":"000000","data":{"ok":true}}`)
	}))
	upstream.TLS = &tls.Config{NextProtos: []string{"http/1.1", "h2"}}
	upstream.StartTLS()
	t.Cleanup(upstream.Close)

	var connects atomic.Int32
	proxyAddr, stop := startConnectProxy(t, &connects)
	t.Cleanup(stop)

	previousSkip := skipTLSVerify
	skipTLSVerify = true
	t.Cleanup(func() { skipTLSVerify = previousSkip })

	headers := http.Header{}
	headers.Set("User-Agent", AccountUA)
	headers.Set("Accept", "application/json")
	resp, errDo := doImpersonated(abiboot.HTTPDoRequest{
		Method:  http.MethodGet,
		URL:     upstream.URL + "/points/records",
		Headers: headers,
	}, "http://"+proxyAddr, 8*time.Second)
	if errDo != nil {
		t.Fatalf("doImpersonated: %v", errDo)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, resp.Body)
	}
	if !strings.Contains(string(resp.Body), `"000000"`) {
		t.Fatalf("body = %s, want the upstream JSON", resp.Body)
	}
	if hits.Load() != 1 {
		t.Fatalf("upstream hits = %d, want 1", hits.Load())
	}
	if connects.Load() < 1 {
		t.Fatal("the CONNECT proxy was never used")
	}
}

// A missing proxy is a direct dial. Still uses utls on HTTPS.
func TestImpersonatedDoDirectTLS(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(upstream.Close)

	previousSkip := skipTLSVerify
	skipTLSVerify = true
	t.Cleanup(func() { skipTLSVerify = previousSkip })

	resp, errDo := doImpersonated(abiboot.HTTPDoRequest{
		Method: http.MethodGet,
		URL:    upstream.URL + "/ping",
	}, "", 8*time.Second)
	if errDo != nil {
		t.Fatalf("direct doImpersonated: %v", errDo)
	}
	if resp.StatusCode != 200 || !strings.Contains(string(resp.Body), "ok") {
		t.Fatalf("status=%d body=%s", resp.StatusCode, resp.Body)
	}
}

func startConnectProxy(t *testing.T, connects *atomic.Int32) (addr string, stop func()) {
	t.Helper()
	ln, errListen := net.Listen("tcp", "127.0.0.1:0")
	if errListen != nil {
		t.Fatalf("listen: %v", errListen)
	}
	var wg sync.WaitGroup
	go func() {
		for {
			conn, errAccept := ln.Accept()
			if errAccept != nil {
				return
			}
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				serveCONNECT(c, connects)
			}(conn)
		}
	}()
	return ln.Addr().String(), func() {
		_ = ln.Close()
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
		}
	}
}

func serveCONNECT(conn net.Conn, connects *atomic.Int32) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	br := bufio.NewReader(conn)
	req, errRead := http.ReadRequest(br)
	if errRead != nil {
		return
	}
	if req.Method != http.MethodConnect {
		_, _ = fmt.Fprintf(conn, "HTTP/1.1 405 Method Not Allowed\r\n\r\n")
		return
	}
	connects.Add(1)
	up, errDial := net.DialTimeout("tcp", req.Host, 5*time.Second)
	if errDial != nil {
		_, _ = fmt.Fprintf(conn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer up.Close()
	_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
	if n := br.Buffered(); n > 0 {
		preface, _ := br.Peek(n)
		_, _ = up.Write(preface)
	}
	_ = conn.SetDeadline(time.Time{})
	_ = up.SetDeadline(time.Time{})
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, conn); done <- struct{}{} }()
	go func() { _, _ = io.Copy(conn, up); done <- struct{}{} }()
	<-done
}
