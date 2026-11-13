package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/collegeming/cpa-jethub-plugins/internal/abiboot"
	utls "github.com/refraction-networking/utls"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
	"golang.org/x/net/http2"
	"golang.org/x/net/proxy"
)

// TLS fingerprint impersonation for gateway and account-host traffic.
//
// The official Loomy desktop client is Electron, which uses Chrome's TLS
// stack. HelloChrome_Auto tracks a current Chrome ClientHello (JA3 / JA4).
// HTTP/2 is negotiated through ALPN (`h2`); if the peer picks http/1.1 the
// request is written as HTTP/1.1. Per-account `proxy_url` (http, https,
// socks5) is honoured, including a username and password.
//
// This transport is used ONLY when `impersonatedDo` is set, which happens in
// the c-shared plugin entry (`cliproxy_plugin_init`). Unit tests leave the
// hook nil and keep talking to the fake host over `host.http.do`, so existing
// tests do not open sockets.

// impersonatedDo, when non-nil, is the production upstream transport.
var impersonatedDo func(req abiboot.HTTPDoRequest, proxyURL string, timeout time.Duration) (*pluginapi.HTTPResponse, error)

var (
	helloID       = utls.HelloChrome_Auto
	skipTLSVerify bool
)

// enableImpersonatedTransport installs the utls client. Called from the
// plugin's C entry so tests that never load the .so are unaffected.
func enableImpersonatedTransport() {
	impersonatedDo = doImpersonated
}

// disableImpersonatedTransport restores the host transport. Tests call this
// from resetTestState as a belt-and-braces cleanup.
func disableImpersonatedTransport() {
	impersonatedDo = nil
}

// doImpersonated performs one buffered request through the utls transport.
func doImpersonated(req abiboot.HTTPDoRequest, proxyURL string, timeout time.Duration) (*pluginapi.HTTPResponse, error) {
	if timeout <= 0 {
		timeout = time.Duration(RequestTimeoutMS) * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	target, errURL := url.Parse(req.URL)
	if errURL != nil {
		return nil, transportError("bad_url", "无效的上游地址：%v", errURL)
	}
	body := io.NopCloser(strings.NewReader(""))
	if len(req.Body) > 0 {
		body = io.NopCloser(strings.NewReader(string(req.Body)))
	}
	httpReq, errReq := http.NewRequestWithContext(ctx, req.Method, req.URL, body)
	if errReq != nil {
		return nil, transportError("bad_request", "构造上游请求失败：%v", errReq)
	}
	if req.Headers != nil {
		httpReq.Header = req.Headers.Clone()
	}
	if httpReq.Header.Get("User-Agent") == "" {
		httpReq.Header.Set("User-Agent", settings().clientUA())
	}
	if len(req.Body) > 0 && httpReq.Header.Get("Content-Length") == "" {
		httpReq.ContentLength = int64(len(req.Body))
	}

	resp, errDo := impersonatedRoundTrip(ctx, httpReq, target, proxyURL)
	if errDo != nil {
		return nil, errDo
	}
	defer resp.Body.Close()
	payload, errRead := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if errRead != nil {
		return nil, transportError("read_body", "读取上游响应失败：%v", errRead)
	}
	return &pluginapi.HTTPResponse{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header.Clone(),
		Body:       payload,
	}, nil
}

func impersonatedRoundTrip(ctx context.Context, req *http.Request, target *url.URL, proxyURL string) (*http.Response, error) {
	hostport := targetHostPort(target)
	rawConn, errDial := dialProxy(ctx, hostport, proxyURL, target.Scheme == "https")
	if errDial != nil {
		return nil, transportError("dial", "连接上游失败：%v", errDial)
	}

	if target.Scheme != "https" {
		writeFn := req.Write
		if isHTTPProxy(proxyURL) {
			writeFn = req.WriteProxy
		}
		if errWrite := writeFn(rawConn); errWrite != nil {
			_ = rawConn.Close()
			return nil, transportError("write", "写入上游失败：%v", errWrite)
		}
		resp, errRead := http.ReadResponse(bufio.NewReader(rawConn), req)
		if errRead != nil {
			_ = rawConn.Close()
			return nil, transportError("read", "读取上游失败：%v", errRead)
		}
		resp.Body = &closeConnBody{ReadCloser: resp.Body, conn: rawConn}
		return resp, nil
	}

	sni := target.Hostname()
	cfg := &utls.Config{
		ServerName:         sni,
		NextProtos:         []string{"h2", "http/1.1"},
		InsecureSkipVerify: skipTLSVerify,
	}
	uconn := utls.UClient(rawConn, cfg, helloID)
	if deadline, ok := ctx.Deadline(); ok {
		_ = rawConn.SetDeadline(deadline)
	}
	if errHS := uconn.HandshakeContext(ctx); errHS != nil {
		_ = rawConn.Close()
		return nil, transportError("tls_handshake", "TLS 握手失败：%v", errHS)
	}
	_ = rawConn.SetDeadline(time.Time{})

	alpn := uconn.ConnectionState().NegotiatedProtocol
	if alpn == "h2" {
		h2t := &http2.Transport{}
		cc, errCC := h2t.NewClientConn(uconn)
		if errCC != nil {
			_ = uconn.Close()
			return nil, transportError("http2", "HTTP/2 会话失败：%v", errCC)
		}
		resp, errRT := cc.RoundTrip(req)
		if errRT != nil {
			_ = cc.Close()
			return nil, transportError("http2_roundtrip", "HTTP/2 请求失败：%v", errRT)
		}
		resp.Body = &closeConnBody{ReadCloser: resp.Body, conn: &h2ConnCloser{cc: cc, conn: uconn}}
		return resp, nil
	}

	// HTTP/1.1 (or empty ALPN, which we treat the same way).
	if errWrite := req.Write(uconn); errWrite != nil {
		_ = uconn.Close()
		return nil, transportError("write", "写入上游失败：%v", errWrite)
	}
	resp, errRead := http.ReadResponse(bufio.NewReader(uconn), req)
	if errRead != nil {
		_ = uconn.Close()
		return nil, transportError("read", "读取上游失败：%v", errRead)
	}
	resp.Body = &closeConnBody{ReadCloser: resp.Body, conn: uconn}
	return resp, nil
}

func targetHostPort(u *url.URL) string {
	host := u.Host
	if u.Port() != "" {
		return host
	}
	switch u.Scheme {
	case "https":
		return net.JoinHostPort(u.Hostname(), "443")
	default:
		return net.JoinHostPort(u.Hostname(), "80")
	}
}

func dialProxy(ctx context.Context, hostport, proxyURL string, tlsTarget bool) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 30 * time.Second}
	if strings.TrimSpace(proxyURL) == "" {
		return dialer.DialContext(ctx, "tcp", hostport)
	}
	parsed, errParse := url.Parse(proxyURL)
	if errParse != nil {
		return nil, fmt.Errorf("无效的 proxy_url：%v", errParse)
	}
	switch strings.ToLower(parsed.Scheme) {
	case "socks5", "socks5h":
		auth := &proxy.Auth{}
		if parsed.User != nil {
			auth.User = parsed.User.Username()
			auth.Password, _ = parsed.User.Password()
		} else {
			auth = nil
		}
		socks, errSocks := proxy.SOCKS5("tcp", proxyHostPort(parsed, "1080"), auth, dialer)
		if errSocks != nil {
			return nil, errSocks
		}
		if cd, ok := socks.(proxy.ContextDialer); ok {
			return cd.DialContext(ctx, "tcp", hostport)
		}
		return socks.Dial("tcp", hostport)
	case "http", "https":
		proxyAddr := proxyHostPort(parsed, "80")
		if parsed.Scheme == "https" {
			proxyAddr = proxyHostPort(parsed, "443")
		}
		conn, errDial := dialer.DialContext(ctx, "tcp", proxyAddr)
		if errDial != nil {
			return nil, errDial
		}
		if parsed.Scheme == "https" {
			cfg := &tls.Config{ServerName: parsed.Hostname(), InsecureSkipVerify: skipTLSVerify}
			tconn := tls.Client(conn, cfg)
			if errHS := tconn.HandshakeContext(ctx); errHS != nil {
				_ = conn.Close()
				return nil, errHS
			}
			conn = tconn
		}
		if tlsTarget {
			connect := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", hostport, hostport)
			if parsed.User != nil {
				user := parsed.User.Username()
				pass, _ := parsed.User.Password()
				token := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
				connect += "Proxy-Authorization: Basic " + token + "\r\n"
			}
			connect += "\r\n"
			if _, errWrite := io.WriteString(conn, connect); errWrite != nil {
				_ = conn.Close()
				return nil, errWrite
			}
			br := bufio.NewReader(conn)
			resp, errRead := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
			if errRead != nil {
				_ = conn.Close()
				return nil, errRead
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				_ = conn.Close()
				return nil, fmt.Errorf("proxy CONNECT 返回 HTTP %d", resp.StatusCode)
			}
			// ReadResponse may have buffered the start of the TLS handshake.
			if n := br.Buffered(); n > 0 {
				preface, _ := br.Peek(n)
				conn = &prefacedConn{Conn: conn, r: io.MultiReader(bytes.NewReader(append([]byte(nil), preface...)), conn)}
			}
		}
		return conn, nil
	default:
		return nil, fmt.Errorf("不支持的 proxy_url scheme %q（需要 http、https 或 socks5）", parsed.Scheme)
	}
}

func proxyHostPort(u *url.URL, defaultPort string) string {
	if u.Port() != "" {
		return u.Host
	}
	return net.JoinHostPort(u.Hostname(), defaultPort)
}

// closeConnBody closes the underlying connection when the response body is
// closed, so a buffered caller (the only kind we have) does not leak sockets.
type closeConnBody struct {
	io.ReadCloser
	conn io.Closer
	once sync.Once
}

func (c *closeConnBody) Close() error {
	var errBody, errConn error
	c.once.Do(func() {
		errBody = c.ReadCloser.Close()
		if c.conn != nil {
			errConn = c.conn.Close()
		}
	})
	if errBody != nil {
		return errBody
	}
	return errConn
}

type h2ConnCloser struct {
	cc   *http2.ClientConn
	conn io.Closer
}

func (c *h2ConnCloser) Close() error {
	errCC := c.cc.Close()
	errConn := c.conn.Close()
	if errCC != nil {
		return errCC
	}
	return errConn
}

func isHTTPProxy(proxyURL string) bool {
	parsed, err := url.Parse(strings.TrimSpace(proxyURL))
	if err != nil || parsed == nil {
		return false
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https":
		return true
	}
	return false
}

// prefacedConn prepends bytes that a bufio.Reader already consumed so a
// subsequent TLS handshake on a CONNECT tunnel sees a complete stream.
type prefacedConn struct {
	net.Conn
	r io.Reader
}

func (c *prefacedConn) Read(p []byte) (int, error) { return c.r.Read(p) }
