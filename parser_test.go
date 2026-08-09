package shield

import (
	"net/netip"
	"strings"
	"testing"
)

func TestParseFeed(t *testing.T) {
	input := "\ufeff# generated feed\n" +
		"192.0.2.1 # inline comment\n" +
		"198.51.100.42/24\n" +
		"2001:db8::1 score-column\n" +
		"::ffff:203.0.113.0/120\n" +
		"not-an-address\n" +
		"\n"

	prefixes, stats, err := parseFeed(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parseFeed() error = %v", err)
	}
	if stats != (ParseStats{Lines: 7, Accepted: 4, Ignored: 2, Invalid: 1}) {
		t.Errorf("stats = %+v", stats)
	}

	want := []netip.Prefix{
		netip.MustParsePrefix("192.0.2.1/32"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("2001:db8::1/128"),
		netip.MustParsePrefix("203.0.113.0/24"),
	}
	if len(prefixes) != len(want) {
		t.Fatalf("prefixes = %v, want %v", prefixes, want)
	}
	for i := range want {
		if prefixes[i] != want[i] {
			t.Errorf("prefixes[%d] = %s, want %s", i, prefixes[i], want[i])
		}
	}
}

func TestParseFeedLimits(t *testing.T) {
	t.Run("line size", func(t *testing.T) {
		_, _, err := parseFeed(strings.NewReader(strings.Repeat("1", maxFeedLineSize+1)))
		if err == nil {
			t.Fatal("parseFeed() error = nil")
		}
	})

	t.Run("entry count", func(t *testing.T) {
		_, _, err := parseFeedLimited(strings.NewReader("192.0.2.1\n192.0.2.2\n"), 1)
		if err == nil {
			t.Fatal("parseFeedLimited() error = nil")
		}
	})
}
