package mamori

import (
	"crypto/tls"
	"log/slog"
	"net/http"
	"net/http/httptrace"
	"time"
)

// WithLogger logs every HTTP round trip (including redirects) and its
// connection phases at debug level: DNS lookup, TCP connect, TLS handshake,
// request written and first response byte. Use it to find out where a
// request stalls:
//
//	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})
//	c, err := mamori.New(url, mamori.WithLogger(slog.New(h)))
//
// Request bodies, cookies and headers are never logged.
func WithLogger(l *slog.Logger) Option {
	return func(c *Client) { c.logger = l }
}

// loggingTransport wraps a RoundTripper with debug logging.
type loggingTransport struct {
	next http.RoundTripper
	log  *slog.Logger
}

func (t *loggingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	start := time.Now()
	since := func() slog.Attr { return slog.Duration("elapsed", time.Since(start).Round(time.Millisecond)) }
	l := t.log.With("method", req.Method, "url", req.URL.Redacted())

	trace := &httptrace.ClientTrace{
		DNSDone: func(i httptrace.DNSDoneInfo) {
			l.Debug("mamori: dns done", "addrs", i.Addrs, "err", i.Err, since())
		},
		ConnectStart: func(network, addr string) {
			l.Debug("mamori: connecting", "addr", addr, since())
		},
		ConnectDone: func(network, addr string, err error) {
			l.Debug("mamori: connected", "addr", addr, "err", err, since())
		},
		TLSHandshakeDone: func(s tls.ConnectionState, err error) {
			l.Debug("mamori: tls handshake done", "proto", s.NegotiatedProtocol, "err", err, since())
		},
		GotConn: func(i httptrace.GotConnInfo) {
			l.Debug("mamori: got connection", "reused", i.Reused, since())
		},
		WroteRequest: func(i httptrace.WroteRequestInfo) {
			l.Debug("mamori: request sent", "err", i.Err, since())
		},
		GotFirstResponseByte: func() {
			l.Debug("mamori: first response byte", since())
		},
	}
	l.Debug("mamori: request start")
	resp, err := t.next.RoundTrip(req.WithContext(httptrace.WithClientTrace(req.Context(), trace)))
	if err != nil {
		l.Debug("mamori: request failed", "err", err, since())
		return nil, err
	}
	attrs := []any{"status", resp.Status, since()}
	if loc := resp.Header.Get("Location"); loc != "" {
		attrs = append(attrs, "location", loc)
	}
	l.Debug("mamori: response", attrs...)
	return resp, nil
}
