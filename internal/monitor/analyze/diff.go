package analyze

import (
	"strconv"
	"strings"
)

// Hunk is one section of a unified diff.
type Hunk struct {
	Header   string
	OldStart int
	NewStart int
	Lines    []Line
}

// Line is one line inside a hunk.
type Line struct {
	// Kind is '-', '+' or ' '.
	Kind byte
	Text string
	// OldLine and NewLine are the 1-based line numbers, zero when not present
	// on that side.
	OldLine int
	NewLine int
}

// Removed reports whether the line was deleted.
func (l Line) Removed() bool { return l.Kind == '-' }

// Added reports whether the line was inserted.
func (l Line) Added() bool { return l.Kind == '+' }

// ParseHunks reads a unified diff patch as returned by the GitHub API.
//
// Line numbers are tracked so a finding can cite a real position rather than
// just quoting text, which is the difference between evidence a reviewer can
// follow and a claim they have to take on trust.
func ParseHunks(patch string) []Hunk {
	if patch == "" {
		return nil
	}
	var out []Hunk
	var cur *Hunk
	oldLine, newLine := 0, 0
	for _, raw := range strings.Split(patch, "\n") {
		if strings.HasPrefix(raw, "@@") {
			h := Hunk{Header: raw}
			h.OldStart, h.NewStart = parseHunkHeader(raw)
			oldLine, newLine = h.OldStart, h.NewStart
			out = append(out, h)
			cur = &out[len(out)-1]
			continue
		}
		if cur == nil {
			continue
		}
		if raw == "" {
			continue
		}
		switch raw[0] {
		case '-':
			cur.Lines = append(cur.Lines, Line{Kind: '-', Text: raw[1:], OldLine: oldLine})
			oldLine++
		case '+':
			cur.Lines = append(cur.Lines, Line{Kind: '+', Text: raw[1:], NewLine: newLine})
			newLine++
		case ' ':
			cur.Lines = append(cur.Lines, Line{Kind: ' ', Text: raw[1:], OldLine: oldLine, NewLine: newLine})
			oldLine++
			newLine++
		case '\\':
			// "\ No newline at end of file" carries no content.
		default:
			// Unrecognised prefixes are treated as context so line numbers do
			// not drift.
			cur.Lines = append(cur.Lines, Line{Kind: ' ', Text: raw, OldLine: oldLine, NewLine: newLine})
			oldLine++
			newLine++
		}
	}
	return out
}

// parseHunkHeader reads "@@ -12,7 +12,9 @@" into its start line numbers.
func parseHunkHeader(h string) (oldStart, newStart int) {
	fields := strings.Fields(h)
	for _, f := range fields {
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case '-':
			oldStart = leadingInt(f[1:])
		case '+':
			newStart = leadingInt(f[1:])
		}
	}
	if oldStart == 0 {
		oldStart = 1
	}
	if newStart == 0 {
		newStart = 1
	}
	return oldStart, newStart
}

func leadingInt(s string) int {
	if i := strings.IndexByte(s, ','); i >= 0 {
		s = s[:i]
	}
	n, _ := strconv.Atoi(s)
	return n
}

// Snippet renders a hunk for evidence, capped so a finding cannot embed a
// thousand-line diff.
func Snippet(h Hunk, around int, maxLines int) string {
	if maxLines <= 0 {
		maxLines = 40
	}
	var b strings.Builder
	b.WriteString(h.Header)
	b.WriteByte('\n')
	n := 0
	for _, l := range h.Lines {
		if n >= maxLines {
			b.WriteString("… (truncated)\n")
			break
		}
		b.WriteByte(l.Kind)
		b.WriteString(l.Text)
		b.WriteByte('\n')
		n++
	}
	return b.String()
}

// commentPrefixes are the line-comment markers of the languages an upstream is
// likely to be written in. A path disappearing from a comment is a
// documentation edit, not an API change.
var commentPrefixes = []string{"//", "#", "--", "*", "/*", "%", ";", "'''", `"""`}

// IsCommentLine reports whether a diff line is only a comment.
func IsCommentLine(text string) bool {
	t := strings.TrimSpace(text)
	if t == "" {
		return false
	}
	for _, p := range commentPrefixes {
		if strings.HasPrefix(t, p) {
			return true
		}
	}
	return false
}

// MethodTokens are HTTP verbs as they appear in source, used to tell a route
// declaration from an incidental string.
var MethodTokens = []string{
	"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS",
	"Get", "Post", "Put", "Patch", "Delete",
}

// HasMethodToken reports whether a line mentions an HTTP verb, which makes a
// path literal on it far more likely to be a real route.
func HasMethodToken(text string) bool {
	for _, m := range MethodTokens {
		if strings.Contains(text, m) {
			return true
		}
	}
	return false
}

// BreakingChangeMarkers appear in changelogs and commit messages that announce
// an incompatible change.
var BreakingChangeMarkers = []string{
	"BREAKING CHANGE", "BREAKING-CHANGE", "breaking change", "no longer",
	"incompatible", "must now", "has been removed", "was removed",
	"has been renamed", "was renamed",
}

// MentionsBreakingChange reports whether text announces an incompatible change.
func MentionsBreakingChange(text string) bool {
	lower := strings.ToLower(text)
	for _, m := range BreakingChangeMarkers {
		if strings.Contains(lower, strings.ToLower(m)) {
			return true
		}
	}
	// Conventional commits mark a break with "type!:".
	for _, line := range strings.Split(text, "\n") {
		if i := strings.Index(line, "!:"); i > 0 && i < 20 {
			return true
		}
	}
	return false
}
