package shield

import (
	"fmt"
	"net/netip"
	"testing"
)

var benchmarkLookupResult bool

// BenchmarkIPLookup measures the request-path membership checks against
// dispersed IPv4 entries. Set construction is intentionally outside the timed
// sections because refresh workers build and publish sets asynchronously.
func BenchmarkIPLookup(b *testing.B) {
	for _, size := range []int{10_000, 100_000, 1_000_000} {
		b.Run(fmt.Sprintf("entries_%d", size), func(b *testing.B) {
			blocked := make([]netip.Prefix, size)
			for i := range blocked {
				blocked[i] = netip.PrefixFrom(benchmarkIPv4(uint32(i)), 32)
			}

			hit := benchmarkIPv4(uint32(size / 2))
			miss := benchmarkIPv4(uint32(size))
			policy, err := newSnapshot(nil, blocked)
			if err != nil {
				b.Fatal(err)
			}
			allowOverride, err := newSnapshot([]netip.Prefix{netip.PrefixFrom(hit, 32)}, blocked)
			if err != nil {
				b.Fatal(err)
			}

			b.Run("deny_hit", func(b *testing.B) {
				benchmarkContainsBlocked(b, policy, hit, true)
			})
			b.Run("allow_override", func(b *testing.B) {
				benchmarkContainsBlocked(b, allowOverride, hit, false)
			})
			b.Run("miss", func(b *testing.B) {
				benchmarkContainsBlocked(b, policy, miss, false)
			})
		})
	}
}

func benchmarkContainsBlocked(b *testing.B, policy *snapshot, address netip.Addr, want bool) {
	b.Helper()
	b.ReportAllocs()
	b.ResetTimer()
	var got bool
	for b.Loop() {
		got = policy.containsBlocked(address)
	}
	benchmarkLookupResult = got
	if got != want {
		b.Fatalf("containsBlocked() = %t, want %t", got, want)
	}
}

// Multiplication by an odd number permutes uint32 values, producing unique,
// non-adjacent addresses without randomness or benchmark setup collisions.
func benchmarkIPv4(index uint32) netip.Addr {
	value := index*2_654_435_761 + 1_013_904_223
	return netip.AddrFrom4([4]byte{
		byte(value >> 24),
		byte(value >> 16),
		byte(value >> 8),
		byte(value),
	})
}
