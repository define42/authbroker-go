package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
)

func TestFirstACMEIssuerNil(t *testing.T) {
	if got := firstACMEIssuer(&certmagic.Config{}); got != nil {
		t.Fatalf("expected nil, got %#v", got)
	}
}

func TestNewACMEServersBuildsBothServers(t *testing.T) {
	broker := newLogoutTestBroker(t)
	acme := ACMEConfig{HTTPAddr: ":0", HTTPSAddr: ":0", Domains: []string{"example.com"}}
	httpsSrv, httpSrv := newACMEServers(broker, acme, &certmagic.Config{}, &tls.Config{MinVersion: tls.VersionTLS12})
	if httpsSrv == nil || httpSrv == nil {
		t.Fatal("nil server returned")
	}
	if httpsSrv.Handler == nil || httpSrv.Handler == nil {
		t.Fatal("server handler missing")
	}
}

func TestNewACMEHTTPHandlerWithNilIssuer(t *testing.T) {
	handler := newACMEHTTPHandler(&certmagic.Config{}, []string{"example.com"})
	if handler == nil {
		t.Fatal("nil handler")
	}
	req := httptest.NewRequest(http.MethodGet, "http://example.com/anything", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusMovedPermanently {
		t.Fatalf("expected redirect, got status %d", rr.Code)
	}
}

func TestListenACMEReportsBindError(t *testing.T) {
	// Reserve a port so the HTTP bind fails after HTTPS succeeds on :0.
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer occupied.Close()

	acme := ACMEConfig{HTTPSAddr: "127.0.0.1:0", HTTPAddr: occupied.Addr().String()}
	httpsL, httpL, err := listenACME(acme, &tls.Config{MinVersion: tls.VersionTLS12})
	if err == nil {
		if httpsL != nil {
			_ = httpsL.Close()
		}
		if httpL != nil {
			_ = httpL.Close()
		}
		t.Fatal("expected bind error for second listener")
	}
}

func TestListenACMERejectsBadHTTPSAddress(t *testing.T) {
	if _, _, err := listenACME(ACMEConfig{HTTPSAddr: "not-an-addr", HTTPAddr: "127.0.0.1:0"}, &tls.Config{MinVersion: tls.VersionTLS12}); err == nil {
		t.Fatal("expected bad address to fail")
	}
}

func TestWaitForACMEStopOnContextDone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := waitForACMEStop(ctx, make(chan error)); err != nil {
		t.Fatalf("ctx done should produce nil err, got %v", err)
	}
}

func TestWaitForACMEStopSurfacesServeError(t *testing.T) {
	ch := make(chan error, 1)
	ch <- errors.New("serve died")
	if err := waitForACMEStop(context.Background(), ch); err == nil {
		t.Fatal("expected serve error to surface")
	}
}

func TestShutdownACMEGracefullyShutsDownServers(_ *testing.T) {
	httpsSrv := &http.Server{Addr: "127.0.0.1:0", ReadHeaderTimeout: time.Second}
	httpSrv := &http.Server{Addr: "127.0.0.1:0", ReadHeaderTimeout: time.Second}
	shutdownACME(httpsSrv, httpSrv)
}

func TestServeACMENotifiesOnFailedStart(t *testing.T) {
	httpsSrv := &http.Server{Handler: http.NewServeMux(), ReadHeaderTimeout: time.Second}
	httpSrv := &http.Server{Handler: http.NewServeMux(), ReadHeaderTimeout: time.Second}

	// Listeners that are already closed will cause Serve to fail immediately
	// with an error other than http.ErrServerClosed, which is what we want to
	// exercise the error path.
	httpsListener := newClosedListener(t)
	httpListener := newClosedListener(t)

	errCh := serveACME(ACMEConfig{Domains: []string{"example.com"}, HTTPSAddr: ":0", HTTPAddr: ":0"}, "issuer", httpsSrv, httpSrv, httpsListener, httpListener)
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected error from closed listener")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("did not receive error in time")
	}
}

type closedListener struct {
	addr net.Addr
}

func newClosedListener(t *testing.T) *closedListener {
	t.Helper()
	return &closedListener{addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}}
}

func (l *closedListener) Accept() (net.Conn, error) {
	return nil, fmt.Errorf("closed listener")
}

func (l *closedListener) Close() error   { return nil }
func (l *closedListener) Addr() net.Addr { return l.addr }
