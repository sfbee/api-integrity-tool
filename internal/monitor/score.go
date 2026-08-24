package monitor

import (
	"strings"

	"github.com/sfbee/api-integrity-tool/internal/model"
)

// Confidence thresholds. A finding below DropBelow is not reported at all
// unless the caller asks for everything.
const (
	DemoteBreakingBelow = 0.70
	DemoteRiskyBelow    = 0.40
	DropBelow           = 0.25
)

// SignalPrior is how much a class of evidence is trusted before anything else
// is considered. A structural specification diff states an interface change
// outright; a path literal vanishing from a diff line is a hint.
func SignalPrior(signal string) float64 {
	switch {
	case strings.HasPrefix(signal, "openapi."):
		return 0.95
	case strings.HasPrefix(signal, "route."):
		return 0.85
	case strings.HasPrefix(signal, "diff."):
		return 0.60
	case strings.HasPrefix(signal, "text."):
		return 0.45
	case strings.HasPrefix(signal, "release."), strings.HasPrefix(signal, "changelog."):
		return 0.35
	default:
		return 0.50
	}
}

// MatchQuality describes how firmly the change was tied to my endpoint.
type MatchQuality float64

const (
	// MatchExact is an identical path literal.
	MatchExact MatchQuality = 1.0
	// MatchTemplate is the same route with differently named placeholders.
	MatchTemplate MatchQuality = 0.9
	// MatchVariant is the same route written in another framework's syntax.
	MatchVariant MatchQuality = 0.8
	// MatchHost means only the host matched, not a specific path.
	MatchHost MatchQuality = 0.5
)

// Rate combines the four independent factors into a confidence and a final
// severity.
//
// The rules are deliberately explicit rather than tuned weights, because a
// severity a user cannot predict is a severity they stop believing. Confidence
// only ever lowers severity: a finding is never promoted automatically, since
// that is precisely how these tools become noisy and get ignored.
func Rate(signal string, proposed model.Severity, match MatchQuality, fileWeight, indexConfidence float64) (model.Severity, float64) {
	if fileWeight <= 0 {
		fileWeight = 1
	}
	if indexConfidence <= 0 {
		indexConfidence = 0.5
	}
	conf := SignalPrior(signal) * float64(match) * fileWeight * indexConfidence

	sev := proposed
	if sev == model.SeverityBreaking && conf < DemoteBreakingBelow {
		sev = model.SeverityRisky
	}
	if sev == model.SeverityRisky && conf < DemoteRiskyBelow {
		sev = model.SeverityInfo
	}
	return sev, round2(conf)
}

// Cap lowers a severity to a ceiling, used where a class of file may not
// justify the strongest verdict however confident the match.
func Cap(sev model.Severity, ceiling model.Severity) model.Severity {
	if sev.Rank() < ceiling.Rank() {
		return ceiling
	}
	return sev
}

func round2(f float64) float64 {
	return float64(int(f*100+0.5)) / 100
}
