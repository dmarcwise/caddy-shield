package shield

import (
	"net/netip"
	"testing"
)

func TestEffectiveStaticPolicy(t *testing.T) {
	global, err := newSnapshot(
		[]netip.Prefix{netip.MustParsePrefix("192.0.2.42/32")},
		[]netip.Prefix{
			netip.MustParsePrefix("198.51.100.0/24"),
			netip.MustParsePrefix("2001:db8::/32"),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	effective, err := extendSnapshot(global,
		[]netip.Prefix{netip.MustParsePrefix("198.51.100.5/32")},
		[]netip.Prefix{
			netip.MustParsePrefix("192.0.2.0/24"),
			netip.MustParsePrefix("203.0.113.0/24"),
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		address string
		blocked bool
	}{
		{address: "192.0.2.42", blocked: false}, // global allow overrides local deny
		{address: "192.0.2.43", blocked: true},
		{address: "198.51.100.5", blocked: false}, // local allow overrides global deny
		{address: "198.51.100.6", blocked: true},
		{address: "::ffff:203.0.113.1", blocked: true},
		{address: "2001:db8::1", blocked: true},
		{address: "2001:db9::1", blocked: false},
	}
	for _, tt := range tests {
		t.Run(tt.address, func(t *testing.T) {
			if got := effective.containsBlocked(netip.MustParseAddr(tt.address)); got != tt.blocked {
				t.Errorf("containsBlocked() = %t, want %t", got, tt.blocked)
			}
		})
	}
}
