package shield

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"strings"
)

const maxFeedLineSize = 1024 * 1024

// ParseStats describes how a feed was interpreted. Invalid entries are
// retained as a count so refresh policy can reject unexpectedly malformed
// feeds without making the parser format-specific.
type ParseStats struct {
	Lines    int
	Accepted int
	Ignored  int
	Invalid  int
}

// parseFeed parses an IP list containing addresses or CIDR prefixes. Blank
// lines and comments are ignored. Additional whitespace-delimited columns are
// permitted so scored feeds can be consumed without a custom parser.
func parseFeed(r io.Reader) ([]netip.Prefix, ParseStats, error) {
	return parseFeedLimited(r, 0)
}

func parseFeedLimited(r io.Reader, maxEntries int) ([]netip.Prefix, ParseStats, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), maxFeedLineSize)

	var (
		prefixes []netip.Prefix
		stats    ParseStats
	)
	for scanner.Scan() {
		stats.Lines++
		line := strings.TrimPrefix(scanner.Text(), "\ufeff")
		if comment := strings.IndexByte(line, '#'); comment >= 0 {
			line = line[:comment]
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			stats.Ignored++
			continue
		}

		prefix, err := parsePrefix(fields[0])
		if err != nil {
			stats.Invalid++
			continue
		}
		if maxEntries > 0 && len(prefixes) >= maxEntries {
			return nil, stats, fmt.Errorf("feed exceeds maximum of %d entries", maxEntries)
		}
		prefixes = append(prefixes, prefix)
		stats.Accepted++
	}
	if err := scanner.Err(); err != nil {
		return nil, stats, fmt.Errorf("scan feed: %w", err)
	}
	return prefixes, stats, nil
}

func parsePrefix(value string) (netip.Prefix, error) {
	if strings.Contains(value, "/") {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return netip.Prefix{}, err
		}
		return normalizePrefix(prefix)
	}

	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Prefix{}, err
	}
	addr = addr.Unmap()
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

func normalizePrefix(prefix netip.Prefix) (netip.Prefix, error) {
	addr := prefix.Addr()
	bits := prefix.Bits()
	if addr.Is4In6() {
		if bits < 96 {
			return netip.Prefix{}, fmt.Errorf("IPv4-mapped prefix length %d cannot be represented as IPv4", bits)
		}
		addr = addr.Unmap()
		bits -= 96
	}
	return netip.PrefixFrom(addr, bits).Masked(), nil
}

func parseConfiguredPrefixes(values []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := parsePrefix(value)
		if err != nil {
			return nil, fmt.Errorf("parse %q: %w", value, err)
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}
