package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type requestIDContextKey struct{}

func newRequestLogger(out io.Writer) *slog.Logger {
	if out == nil {
		out = os.Stderr
	}
	return slog.New(slog.NewJSONHandler(out, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

func requestIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(requestIDContextKey{}).(string)
	return id
}

func (b *Broker) observability(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := cleanRequestID(r.Header.Get("X-Request-ID"))
		if requestID == "" {
			requestID = randomB64(16)
		}
		w.Header().Set("X-Request-ID", requestID)
		ctx := context.WithValue(r.Context(), requestIDContextKey{}, requestID)
		r = r.WithContext(ctx)

		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()
		next.ServeHTTP(rec, r)
		duration := time.Since(start)

		path := metricPath(r.URL.Path, b.cfg.Metrics.Path)
		if b.metrics != nil {
			b.metrics.record(r.Method, path, rec.status, duration)
		}
		if b.requestLog != nil {
			b.requestLog.LogAttrs(ctx, slog.LevelInfo, "request",
				slog.String("request_id", requestID),
				slog.String("method", r.Method),
				slog.String("path", path),
				slog.Int("status", rec.status),
				slog.Int("bytes", rec.bytes),
				slog.Int64("duration_ms", duration.Milliseconds()),
				slog.String("client_ip", b.clientIP(r)),
			)
		}
	})
}

type statusRecorder struct {
	http.ResponseWriter

	status int
	bytes  int
	wrote  bool
}

func (r *statusRecorder) WriteHeader(status int) {
	if r.wrote {
		return
	}
	r.wrote = true
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if !r.wrote {
		r.WriteHeader(http.StatusOK)
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += n
	return n, err
}

func cleanRequestID(id string) string {
	id = strings.TrimSpace(id)
	if len(id) > 128 || strings.ContainsAny(id, "\r\n\t") {
		return ""
	}
	return id
}

type metricsRegistry struct {
	mu       sync.Mutex
	requests map[metricKey]*requestMetric
}

type metricKey struct {
	method string
	path   string
	status int
}

type requestMetric struct {
	count       int64
	durationSum float64
}

func newMetricsRegistry() *metricsRegistry {
	return &metricsRegistry{requests: map[metricKey]*requestMetric{}}
}

func (m *metricsRegistry) record(method, path string, status int, duration time.Duration) {
	if m == nil {
		return
	}
	key := metricKey{method: method, path: path, status: status}
	m.mu.Lock()
	defer m.mu.Unlock()
	metric := m.requests[key]
	if metric == nil {
		metric = &requestMetric{}
		m.requests[key] = metric
	}
	metric.count++
	metric.durationSum += duration.Seconds()
}

func (m *metricsRegistry) render() string {
	if m == nil {
		return ""
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	keys := make([]metricKey, 0, len(m.requests))
	for key := range m.requests {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].path != keys[j].path {
			return keys[i].path < keys[j].path
		}
		if keys[i].method != keys[j].method {
			return keys[i].method < keys[j].method
		}
		return keys[i].status < keys[j].status
	})

	var b strings.Builder
	b.WriteString("# HELP authbroker_http_requests_total Total HTTP requests by method, path, and status.\n")
	b.WriteString("# TYPE authbroker_http_requests_total counter\n")
	b.WriteString("# HELP authbroker_http_request_duration_seconds_sum Total HTTP request duration by method, path, and status.\n")
	b.WriteString("# TYPE authbroker_http_request_duration_seconds_sum counter\n")
	for _, key := range keys {
		labels := metricLabels(key)
		metric := m.requests[key]
		fmt.Fprintf(&b, "authbroker_http_requests_total{%s} %d\n", labels, metric.count)
		fmt.Fprintf(&b, "authbroker_http_request_duration_seconds_sum{%s} %.6f\n", labels, metric.durationSum)
	}
	return b.String()
}

func metricLabels(key metricKey) string {
	return fmt.Sprintf("method=%q,path=%q,status=%q",
		escapeMetricLabel(key.method),
		escapeMetricLabel(key.path),
		strconv.Itoa(key.status),
	)
}

func escapeMetricLabel(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, "\n", `\n`)
	return strings.ReplaceAll(value, `"`, `\"`)
}

// metricPath normalizes templated request paths so that one metric series is
// emitted per route pattern (rather than per concrete URL with embedded IDs).
//
// MAINTENANCE: when adding a new route in (*Broker).buildRoutes that uses a
// path parameter — e.g. `/foo/{id}` — add a matching case here. Otherwise
// the metric label space will grow unbounded with one series per id, and
// Prometheus scrapes will explode. net/http.ServeMux does not expose its
// registered patterns, which is why this is a hand-maintained list.
func metricPath(path, metricsPath string) string {
	switch {
	case path == "":
		return "/"
	case metricsPath != "" && path == metricsPath:
		return metricsPath
	case strings.HasPrefix(path, "/admin/clients/") && strings.HasSuffix(path, "/delete"):
		return "/admin/clients/{id}/delete"
	case strings.HasPrefix(path, "/admin/app-tokens/") && strings.HasSuffix(path, "/delete"):
		return "/admin/app-tokens/{id}/delete"
	case strings.HasPrefix(path, "/app-tokens/"):
		return "/app-tokens/{id}"
	default:
		return path
	}
}
