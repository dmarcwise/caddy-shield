package shield

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

func TestManagerRefreshesIndependentlyAndRetainsLastGood(t *testing.T) {
	slowStarted := make(chan struct{})
	releaseSlow := make(chan struct{})
	var slowStartOnce, releaseOnce sync.Once
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		slowStartOnce.Do(func() { close(slowStarted) })
		<-releaseSlow
		_, _ = w.Write([]byte("192.0.2.1\n"))
	}))
	defer slow.Close()

	var fastRequests atomic.Int32
	fastFailed := make(chan struct{})
	var fastFailOnce sync.Once
	fast := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if fastRequests.Add(1) == 1 {
			_, _ = w.Write([]byte("198.51.100.1\n"))
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		fastFailOnce.Do(func() { close(fastFailed) })
	}))
	defer fast.Close()

	app := &App{
		Sources: []Source{
			{Name: "slow", URL: slow.URL, RefreshInterval: caddy.Duration(time.Hour)},
			{Name: "fast", URL: fast.URL, RefreshInterval: caddy.Duration(20 * time.Millisecond)},
		},
		RefreshInterval: caddy.Duration(time.Hour),
		Timeout:         caddy.Duration(5 * time.Second),
		MaxSize:         1024,
		MaxEntries:      100,
		logger:          zap.NewNop(),
	}
	manager, err := newRefreshManager(context.Background(), app)
	if err != nil {
		t.Fatal(err)
	}
	manager.Start()
	defer manager.Stop()
	defer releaseOnce.Do(func() { close(releaseSlow) })

	waitSignal(t, slowStarted, "slow source did not start")
	waitForAddress(t, manager, "198.51.100.1")
	if manager.Snapshot().blocked.Contains(netip.MustParseAddr("192.0.2.1")) {
		t.Fatal("slow source was published before it completed")
	}

	waitSignal(t, fastFailed, "fast source was not refreshed")
	if !manager.Snapshot().blocked.Contains(netip.MustParseAddr("198.51.100.1")) {
		t.Fatal("failed refresh discarded the fast source's last-known-good data")
	}

	releaseOnce.Do(func() { close(releaseSlow) })
	waitForAddress(t, manager, "192.0.2.1")
	if !manager.Snapshot().blocked.Contains(netip.MustParseAddr("198.51.100.1")) {
		t.Fatal("publishing the slow source discarded the fast source")
	}
}

func TestManagerStopCancelsInFlightFetch(t *testing.T) {
	started := make(chan struct{})
	cancelled := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
		close(cancelled)
	}))
	defer server.Close()

	app := &App{
		Sources:         []Source{{Name: "blocked", URL: server.URL}},
		RefreshInterval: caddy.Duration(time.Hour),
		Timeout:         caddy.Duration(time.Hour),
		MaxSize:         1024,
		MaxEntries:      100,
		logger:          zap.NewNop(),
	}
	manager, err := newRefreshManager(context.Background(), app)
	if err != nil {
		t.Fatal(err)
	}
	manager.Start()
	waitSignal(t, started, "source fetch did not start")
	manager.Stop()
	waitSignal(t, cancelled, "source request was not cancelled")
	if manager.Snapshot().ready {
		t.Fatal("cancelled source was published")
	}
}

func TestManagerConcurrentPublication(t *testing.T) {
	app := &App{
		Sources:         []Source{{Name: "test", URL: "https://example.test/list"}},
		RefreshInterval: caddy.Duration(time.Hour),
		Timeout:         caddy.Duration(time.Second),
		MaxSize:         1024,
		MaxEntries:      100,
		logger:          zap.NewNop(),
	}
	manager, err := newRefreshManager(context.Background(), app)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Stop()

	sets := make([]*feedSnapshot, 2)
	for i, prefix := range []string{"192.0.2.0/24", "198.51.100.0/24"} {
		set, err := buildIPSet([]netip.Prefix{netip.MustParsePrefix(prefix)})
		if err != nil {
			t.Fatal(err)
		}
		sets[i] = &feedSnapshot{blocked: set, ready: true}
	}

	var readers sync.WaitGroup
	for range 8 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for range 5_000 {
				snapshot := manager.Snapshot()
				_ = snapshot.blocked.Contains(netip.MustParseAddr("192.0.2.1"))
				runtime.Gosched()
			}
		}()
	}
	for i := range 5_000 {
		set := sets[i%len(sets)].blocked
		manager.publish(manager.sources[0], fetchResult{set: set, statusCode: http.StatusOK}, 0)
	}
	readers.Wait()

	if snapshot := manager.Snapshot(); !snapshot.ready {
		t.Fatal("published snapshot is not ready")
	}
}

func waitSignal(t *testing.T, signal <-chan struct{}, message string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatal(message)
	}
}

func waitForAddress(t *testing.T, manager *refreshManager, address string) {
	t.Helper()
	addr := netip.MustParseAddr(address)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if manager.Snapshot().blocked.Contains(addr) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("address %s was not published before timeout", address)
}
