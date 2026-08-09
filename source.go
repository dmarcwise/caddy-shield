package shield

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"go4.org/netipx"
)

const userAgent = "Caddy-Shield"

type sourceRuntime struct {
	name         string
	url          string
	interval     time.Duration
	etag         string
	lastModified string
	set          *netipx.IPSet
}

type fetchResult struct {
	set        *netipx.IPSet
	stats      ParseStats
	statusCode int
}

func (s *sourceRuntime) fetch(
	ctx context.Context,
	client *http.Client,
	maxSize int64,
	maxEntries int,
) (fetchResult, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return fetchResult{}, false, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", "text/plain")
	req.Header.Set("User-Agent", userAgent)
	if s.etag != "" {
		req.Header.Set("If-None-Match", s.etag)
	}
	if s.lastModified != "" {
		req.Header.Set("If-Modified-Since", s.lastModified)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fetchResult{}, false, fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return fetchResult{statusCode: resp.StatusCode}, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		_, _ = io.CopyN(io.Discard, resp.Body, 4*1024)
		return fetchResult{}, false, fmt.Errorf("download: unexpected HTTP status %s", resp.Status)
	}
	if resp.ContentLength > maxSize {
		return fetchResult{}, false, fmt.Errorf("download: content length %d exceeds maximum of %d bytes", resp.ContentLength, maxSize)
	}

	limited := &io.LimitedReader{R: resp.Body, N: maxSize + 1}
	prefixes, stats, err := parseFeedLimited(limited, maxEntries)
	if err != nil {
		return fetchResult{}, false, err
	}
	if limited.N == 0 {
		return fetchResult{}, false, fmt.Errorf("download exceeds maximum of %d bytes", maxSize)
	}
	if stats.Accepted == 0 {
		return fetchResult{}, false, fmt.Errorf("feed contains no valid entries")
	}

	set, err := buildIPSet(prefixes)
	if err != nil {
		return fetchResult{}, false, fmt.Errorf("build source set: %w", err)
	}
	s.etag = resp.Header.Get("ETag")
	s.lastModified = resp.Header.Get("Last-Modified")
	return fetchResult{set: set, stats: stats, statusCode: resp.StatusCode}, true, nil
}
