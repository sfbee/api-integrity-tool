package monitor

import (
	"testing"

	"github.com/stephen-bee/endpoint-monitor/internal/model"
)

func TestRateDemotesLowConfidence(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		signal     string
		proposed   model.Severity
		match      MatchQuality
		fileWeight float64
		indexConf  float64
		wantSev    model.Severity
	}{
		{
			// A specification saying an operation was removed, matched exactly,
			// against a call we are confident about: the strongest possible case.
			"spec removal keeps breaking", "openapi.path_removed",
			model.SeverityBreaking, MatchExact, 1.0, 1.0, model.SeverityBreaking,
		},
		{
			// The same claim from a bare diff line in a test file should not
			// arrive as a breaking change.
			"weak evidence is demoted", "diff.removed_path_literal",
			model.SeverityBreaking, MatchVariant, 0.25, 0.5, model.SeverityInfo,
		},
		{
			"changelog mention alone cannot be breaking", "changelog.breaking",
			model.SeverityBreaking, MatchHost, 1.0, 1.0, model.SeverityInfo,
		},
		{
			"route removal on a real route file stays breaking", "route.removed",
			model.SeverityBreaking, MatchExact, 1.0, 1.0, model.SeverityBreaking,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sev, conf := Rate(tc.signal, tc.proposed, tc.match, tc.fileWeight, tc.indexConf)
			if sev != tc.wantSev {
				t.Errorf("severity = %q (confidence %.2f), want %q", sev, conf, tc.wantSev)
			}
			if conf < 0 || conf > 1 {
				t.Errorf("confidence %.2f out of range", conf)
			}
		})
	}
}

// Severity must never rise. Automatic promotion is how a monitor becomes noisy,
// and noise is indistinguishable from being wrong.
func TestRateNeverPromotes(t *testing.T) {
	t.Parallel()
	for _, proposed := range []model.Severity{model.SeverityInfo, model.SeverityRisky} {
		sev, _ := Rate("openapi.path_removed", proposed, MatchExact, 1.0, 1.0)
		if sev.Rank() < proposed.Rank() {
			t.Errorf("Rate promoted %q to %q", proposed, sev)
		}
	}
}

func TestCap(t *testing.T) {
	t.Parallel()
	if got := Cap(model.SeverityBreaking, model.SeverityRisky); got != model.SeverityRisky {
		t.Errorf("Cap = %q, want risky", got)
	}
	if got := Cap(model.SeverityInfo, model.SeverityRisky); got != model.SeverityInfo {
		t.Errorf("Cap should not raise severity, got %q", got)
	}
}
