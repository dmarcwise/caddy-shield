package shield

import (
	"errors"
	"fmt"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

type decisionMetric uint8

const (
	decisionAllowAllowlist decisionMetric = iota
	decisionAllowNotListed
	decisionAllowUnavailable
	decisionBlockStaticDeny
	decisionBlockSource
	decisionBlockUnavailable
	decisionMetricCount
)

var decisionMetricLabels = [...]struct {
	decision string
	reason   string
}{
	decisionAllowAllowlist:   {decision: "allow", reason: "allowlist"},
	decisionAllowNotListed:   {decision: "allow", reason: "not_listed"},
	decisionAllowUnavailable: {decision: "allow", reason: "unavailable"},
	decisionBlockStaticDeny:  {decision: "block", reason: "static_deny"},
	decisionBlockSource:      {decision: "block", reason: "source"},
	decisionBlockUnavailable: {decision: "block", reason: "unavailable"},
}

type shieldMetrics struct {
	decisions      *prometheus.CounterVec
	sourceBlocks   *prometheus.CounterVec
	decisionCounts [decisionMetricCount]prometheus.Counter
	sourceCounts   map[string]prometheus.Counter
}

type shieldMetricCollectors struct {
	decisions    *prometheus.CounterVec
	sourceBlocks *prometheus.CounterVec
}

var (
	// Caddy replaces its Prometheus registry on config reload. Keep collectors
	// for the process lifetime and register them with every new registry so
	// counters remain active and retain their values. Source series are not
	// deleted on reload because requests using the old config may still be in
	// flight; removed source labels disappear when the process restarts.
	sharedMetricsOnce sync.Once
	sharedMetrics     *shieldMetricCollectors
)

func newShieldMetrics(registry prometheus.Registerer, sources []Source) (*shieldMetrics, error) {
	sharedMetricsOnce.Do(func() {
		sharedMetrics = &shieldMetricCollectors{
			decisions: prometheus.NewCounterVec(prometheus.CounterOpts{
				Namespace: "caddy",
				Subsystem: "shield",
				Name:      "decisions_total",
				Help:      "Number of requests allowed or blocked by Shield.",
			}, []string{"decision", "reason"}),
			sourceBlocks: prometheus.NewCounterVec(prometheus.CounterOpts{
				Namespace: "caddy",
				Subsystem: "shield",
				Name:      "source_blocks_total",
				Help:      "Number of blocked requests matching each Shield source.",
			}, []string{"source"}),
		}
	})
	metrics := &shieldMetrics{
		decisions:    sharedMetrics.decisions,
		sourceBlocks: sharedMetrics.sourceBlocks,
		sourceCounts: make(map[string]prometheus.Counter, len(sources)),
	}
	if err := registerSharedCollector(registry, metrics.decisions); err != nil {
		return nil, fmt.Errorf("register decisions counter: %w", err)
	}
	if err := registerSharedCollector(registry, metrics.sourceBlocks); err != nil {
		return nil, fmt.Errorf("register source blocks counter: %w", err)
	}
	for metric, labels := range decisionMetricLabels {
		metrics.decisionCounts[metric] = metrics.decisions.WithLabelValues(labels.decision, labels.reason)
	}
	for _, source := range sources {
		metrics.sourceCounts[source.Name] = metrics.sourceBlocks.WithLabelValues(source.Name)
	}
	return metrics, nil
}

func registerSharedCollector(registry prometheus.Registerer, collector prometheus.Collector) error {
	err := registry.Register(collector)
	if err == nil {
		return nil
	}
	var alreadyRegistered prometheus.AlreadyRegisteredError
	if errors.As(err, &alreadyRegistered) && alreadyRegistered.ExistingCollector == collector {
		return nil
	}
	return err
}

func (m *shieldMetrics) recordDecision(metric decisionMetric) {
	if m != nil {
		m.decisionCounts[metric].Inc()
	}
}

func (m *shieldMetrics) recordSourceBlocks(sources []string) {
	if m == nil {
		return
	}
	for _, source := range sources {
		if counter := m.sourceCounts[source]; counter != nil {
			counter.Inc()
		}
	}
}
