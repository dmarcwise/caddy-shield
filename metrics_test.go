package shield

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestMetricsRemainActiveAcrossRegistryReload(t *testing.T) {
	sources := []Source{{Name: "reload_test"}}
	firstRegistry := prometheus.NewPedanticRegistry()
	first, err := newShieldMetrics(firstRegistry, sources)
	if err != nil {
		t.Fatal(err)
	}
	counter := first.decisionCounts[decisionBlockSource]
	before := prometheusCounterValue(t, counter)
	first.recordDecision(decisionBlockSource)

	secondRegistry := prometheus.NewPedanticRegistry()
	second, err := newShieldMetrics(secondRegistry, sources)
	if err != nil {
		t.Fatal(err)
	}
	if first.decisions != second.decisions || first.sourceBlocks != second.sourceBlocks {
		t.Fatal("reload created new collectors instead of re-registering the shared collectors")
	}
	second.recordDecision(decisionBlockSource)

	want := before + 2
	got, found := gatheredCounterValue(t, secondRegistry, "caddy_shield_decisions_total", map[string]string{
		"decision": "block",
		"reason":   "source",
	})
	if !found || got != want {
		t.Fatalf("reloaded registry counter = %v, %t; want %v, true", got, found, want)
	}
}

func gatheredCounterValue(t *testing.T, registry *prometheus.Registry, name string, labels map[string]string) (float64, bool) {
	t.Helper()
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.GetMetric() {
			matched := len(metric.GetLabel()) == len(labels)
			for _, label := range metric.GetLabel() {
				if labels[label.GetName()] != label.GetValue() {
					matched = false
					break
				}
			}
			if matched {
				return metric.GetCounter().GetValue(), true
			}
		}
	}
	return 0, false
}
