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
// The patterns come from dynamicRoutePatterns, so buildRoutes and the metric
// label set move in lockstep — adding a new `/foo/{id}` route requires only
// extending dynamicRoutePatterns; no second edit here is needed.
func metricPath(path, metricsPath string) string {
	if path == "" {
		return "/"
	}
	if metricsPath != "" && path == metricsPath {
		return metricsPath
	}
	for _, pattern := range dynamicRoutePatternList {
		if matchDynamicPattern(pattern, path) {
			return pattern
		}
	}
	return path
}

// dynamicRoutePatternList enumerates the patterns metricPath should collapse.
// It is auto-sorted by specificity at init (most segments first; ties broken
// by literal-segment count) so adding a new `/foo/{id}` pattern to
// dynamicRoutePatterns can never accidentally shadow a more specific
// `/foo/{id}/bar` — earlier revisions relied on hand-ordering, which is easy
// to get wrong when a new entry is added.
//
//nolint:gochecknoglobals // Mirrors dynamicRoutePatterns; sorted at init.
var dynamicRoutePatternList = sortDynamicRoutePatterns([]string{
	dynamicRoutePatterns.AdminClientDelete,
	dynamicRoutePatterns.AdminAppTokenDelete,
	dynamicRoutePatterns.AppToken,
})

// sortDynamicRoutePatterns orders patterns by total segment count desc, then
// by literal-segment count desc (segments that don't contain a `{` are
// considered literal), then lexicographically for deterministic output.
func sortDynamicRoutePatterns(patterns []string) []string {
	out := append([]string(nil), patterns...)
	sort.Slice(out, func(i, j int) bool {
		ti, li := routePatternSpecificity(out[i])
		tj, lj := routePatternSpecificity(out[j])
		if ti != tj {
			return ti > tj
		}
		if li != lj {
			return li > lj
		}
		return out[i] < out[j]
	})
	return out
}

func routePatternSpecificity(pattern string) (total, literal int) {
	for _, seg := range strings.Split(pattern, "/") {
		if seg == "" {
			continue
		}
		total++
		if !strings.Contains(seg, "{") {
			literal++
		}
	}
	return total, literal
}

// matchDynamicPattern reports whether path matches pattern, where pattern
// contains exactly one `{id}` segment. The match is segment-aware: a request
// for `/app-tokens/foo/bar` does NOT match `/app-tokens/{id}` even though the
// prefix lines up.
func matchDynamicPattern(pattern, path string) bool {
	idx := strings.Index(pattern, "{id}")
	if idx < 0 {
		return pattern == path
	}
	prefix := pattern[:idx]
	suffix := pattern[idx+len("{id}"):]
	if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, suffix) {
		return false
	}
	middle := path[len(prefix) : len(path)-len(suffix)]
	if middle == "" || strings.Contains(middle, "/") {
		return false
	}
	return true
}
