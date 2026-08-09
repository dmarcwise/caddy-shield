package shield

import (
	"fmt"
	"net/http"
	"net/netip"

	"go4.org/netipx"
)

// snapshot is immutable after construction and safe to share across all
// request goroutines.
type snapshot struct {
	allowed *netipx.IPSet
	blocked *netipx.IPSet
}

func newSnapshot(allowed, blocked []netip.Prefix) (*snapshot, error) {
	allowedSet, err := buildIPSet(allowed)
	if err != nil {
		return nil, fmt.Errorf("build allow set: %w", err)
	}
	blockedSet, err := buildIPSet(blocked)
	if err != nil {
		return nil, fmt.Errorf("build block set: %w", err)
	}
	return &snapshot{allowed: allowedSet, blocked: blockedSet}, nil
}

func newSnapshotFromSets(allowed, blocked *netipx.IPSet) *snapshot {
	return &snapshot{allowed: allowed, blocked: blocked}
}

func extendSnapshot(base *snapshot, allowed, blocked []netip.Prefix) (*snapshot, error) {
	var allowedBuilder, blockedBuilder netipx.IPSetBuilder
	if base != nil {
		allowedBuilder.AddSet(base.allowed)
		blockedBuilder.AddSet(base.blocked)
	}
	for _, prefix := range allowed {
		allowedBuilder.AddPrefix(prefix)
	}
	for _, prefix := range blocked {
		blockedBuilder.AddPrefix(prefix)
	}
	allowedSet, err := allowedBuilder.IPSet()
	if err != nil {
		return nil, fmt.Errorf("build effective allow set: %w", err)
	}
	blockedSet, err := blockedBuilder.IPSet()
	if err != nil {
		return nil, fmt.Errorf("build effective deny set: %w", err)
	}
	return newSnapshotFromSets(allowedSet, blockedSet), nil
}

func mergeResponse(base, override Response) Response {
	merged := Response{
		StatusCode: base.StatusCode,
		Body:       base.Body,
		Headers:    make(map[string][]string, len(base.Headers)+len(override.Headers)),
	}
	for field, values := range base.Headers {
		field = http.CanonicalHeaderKey(field)
		merged.Headers[field] = append([]string(nil), values...)
	}
	for field, values := range override.Headers {
		field = http.CanonicalHeaderKey(field)
		merged.Headers[field] = append([]string(nil), values...)
	}
	if override.StatusCode != 0 {
		merged.StatusCode = override.StatusCode
	}
	if override.Body != nil {
		merged.Body = override.Body
	}
	return merged
}

func buildIPSet(prefixes []netip.Prefix) (*netipx.IPSet, error) {
	var builder netipx.IPSetBuilder
	for _, prefix := range prefixes {
		builder.AddPrefix(prefix)
	}
	return builder.IPSet()
}

// containsBlocked applies the allowlist before the blocklist. Addresses are
// unmapped so IPv4 and IPv4-mapped IPv6 forms have identical behavior.
func (s *snapshot) containsBlocked(addr netip.Addr) bool {
	if s == nil || !addr.IsValid() {
		return false
	}
	addr = addr.Unmap().WithZone("")
	if s.containsAllowed(addr) {
		return false
	}
	return s.blocked.Contains(addr)
}

func (s *snapshot) containsAllowed(addr netip.Addr) bool {
	if s == nil || !addr.IsValid() {
		return false
	}
	return s.allowed.Contains(addr.Unmap().WithZone(""))
}
