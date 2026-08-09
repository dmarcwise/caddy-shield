package shield

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
	"go4.org/netipx"
)

type refreshManager struct {
	ctx       context.Context
	cancel    context.CancelFunc
	client    *http.Client
	transport *http.Transport
	logger    *zap.Logger

	refreshInterval time.Duration
	maxSize         int64
	maxEntries      int
	current         atomic.Pointer[feedSnapshot]
	sources         []*sourceRuntime

	startOnce   sync.Once
	stopOnce    sync.Once
	wg          sync.WaitGroup
	publishMu   sync.Mutex
	lifecycleMu sync.Mutex
	stopped     bool
}

type feedSnapshot struct {
	blocked *netipx.IPSet
	sources []feedSourceSnapshot
	ready   bool
}

type feedSourceSnapshot struct {
	name string
	set  *netipx.IPSet
}

func (s *feedSnapshot) matchingSources(addr netip.Addr) []string {
	if s == nil || !addr.IsValid() {
		return nil
	}
	addr = addr.Unmap().WithZone("")
	matches := make([]string, 0, len(s.sources))
	for _, source := range s.sources {
		if source.set.Contains(addr) {
			matches = append(matches, source.name)
		}
	}
	return matches
}

func newRefreshManager(parent context.Context, app *App) (*refreshManager, error) {
	ctx, cancel := context.WithCancel(parent)
	defaultTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		cancel()
		return nil, fmt.Errorf("default HTTP transport has unexpected type %T", http.DefaultTransport)
	}
	transport := defaultTransport.Clone()
	empty, err := buildIPSet(nil)
	if err != nil {
		cancel()
		return nil, err
	}
	logger := app.logger
	if logger == nil {
		logger = zap.NewNop()
	}
	m := &refreshManager{
		ctx:             ctx,
		cancel:          cancel,
		client:          &http.Client{Transport: transport, Timeout: time.Duration(app.Timeout)},
		transport:       transport,
		logger:          logger,
		refreshInterval: time.Duration(app.RefreshInterval),
		maxSize:         app.MaxSize,
		maxEntries:      app.MaxEntries,
		sources:         make([]*sourceRuntime, 0, len(app.Sources)),
	}
	m.current.Store(&feedSnapshot{blocked: empty, ready: len(app.Sources) == 0})
	for _, configured := range app.Sources {
		url := configured.URL
		if url == "" {
			url = presets[configured.Name]
		}
		interval := time.Duration(configured.RefreshInterval)
		if interval == 0 {
			interval = m.refreshInterval
		}
		m.sources = append(m.sources, &sourceRuntime{
			name:     configured.Name,
			url:      url,
			interval: interval,
		})
	}
	return m, nil
}

// Start launches each source independently and returns without waiting for a
// network request. It is safe to call for every incoming request.
func (m *refreshManager) Start() {
	m.startOnce.Do(func() {
		m.lifecycleMu.Lock()
		defer m.lifecycleMu.Unlock()
		if m.stopped {
			return
		}
		for _, source := range m.sources {
			m.wg.Add(1)
			go m.run(source)
		}
	})
}

func (m *refreshManager) Stop() {
	m.stopOnce.Do(func() {
		m.lifecycleMu.Lock()
		m.stopped = true
		m.cancel()
		m.lifecycleMu.Unlock()
	})
	m.wg.Wait()
	m.transport.CloseIdleConnections()
}

func (m *refreshManager) Snapshot() *feedSnapshot {
	return m.current.Load()
}

func (m *refreshManager) run(source *sourceRuntime) {
	defer m.wg.Done()

	retryDelay := time.Minute
	if source.interval < retryDelay {
		retryDelay = source.interval
	}
	for {
		started := time.Now()
		result, changed, err := source.fetch(m.ctx, m.client, m.maxSize, m.maxEntries)
		duration := time.Since(started)
		if m.ctx.Err() != nil {
			return
		}
		delay := source.interval
		if err != nil {
			m.logger.Warn("blocklist refresh failed",
				zap.String("source", source.name),
				zap.Duration("duration", duration),
				zap.Error(err),
			)
			delay = retryDelay
			retryDelay = nextBackoff(retryDelay, source.interval)
		} else {
			retryDelay = min(time.Minute, source.interval)
			if changed {
				m.publish(source, result, duration)
			} else {
				m.logger.Debug("blocklist unchanged",
					zap.String("source", source.name),
					zap.Int("status", result.statusCode),
					zap.Duration("duration", duration),
				)
			}
		}

		timer := time.NewTimer(jitter(delay))
		select {
		case <-m.ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return
		case <-timer.C:
		}
	}
}

func (m *refreshManager) publish(source *sourceRuntime, result fetchResult, duration time.Duration) {
	m.publishMu.Lock()
	defer m.publishMu.Unlock()

	source.set = result.set
	var builder netipx.IPSetBuilder
	sources := make([]feedSourceSnapshot, 0, len(m.sources))
	for _, configured := range m.sources {
		if configured.set != nil {
			builder.AddSet(configured.set)
			sources = append(sources, feedSourceSnapshot{name: configured.name, set: configured.set})
		}
	}
	blocked, err := builder.IPSet()
	if err != nil {
		m.logger.Error("failed to build combined blocklist snapshot", zap.Error(err))
		return
	}
	m.current.Store(&feedSnapshot{blocked: blocked, sources: sources, ready: true})
	m.logger.Info("blocklist refreshed",
		zap.String("source", source.name),
		zap.Int("status", result.statusCode),
		zap.Duration("duration", duration),
		zap.Int("accepted", result.stats.Accepted),
		zap.Int("invalid", result.stats.Invalid),
		zap.Int("ranges", len(result.set.Ranges())),
	)
}

func nextBackoff(current, maximum time.Duration) time.Duration {
	if current >= maximum || current > maximum-current {
		return maximum
	}
	return current * 2
}

func jitter(delay time.Duration) time.Duration {
	if delay <= 0 {
		return time.Millisecond
	}
	// Spread refreshes by ±10% so instances do not repeatedly hit feeds at the
	// same instant. The scheduler does not require cryptographic randomness.
	spread := delay / 10
	if spread == 0 {
		return delay
	}
	return delay - spread + time.Duration(rand.Int64N(int64(2*spread)+1))
}
