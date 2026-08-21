package lineengine

import (
	"strings"
)

// blankNonCode replaces comments, documentation blocks and post-source markers
// with spaces, leaving every other byte and every newline at its original
// offset. Preserving offsets is what keeps reported line and column numbers
// correct after stripping, and it means the caller can slice the blanked text
// and still index back into the original.
func blankNonCode(src string, spec *Spec) string {
	b := []byte(src)
	blank := func(from, to int) {
		for i := from; i < to && i < len(b); i++ {
			if b[i] != '\n' {
				b[i] = ' '
			}
		}
	}

	// Truncate at end-of-source markers such as Perl's __END__ or __DATA__.
	for _, marker := range spec.SkipAfter {
		if i := indexAtLineStart(src, marker); i >= 0 {
			blank(i, len(b))
		}
	}

	i := 0
	for i < len(b) {
		// A string literal is code: skip over it so a "#" or "//" inside a URL
		// is never mistaken for a comment. The exception is a documentation
		// string standing alone as a statement, which is prose and often
		// contains example calls that must not be indexed.
		if parts, syn, adv, ok := scanString(src, i, spec); ok {
			_ = parts
			if syn.DocString && onlySpaceBeforeOnLine(src, i) {
				blank(i, adv)
			}
			i = adv
			continue
		}
		if spec.PodBlocks && atLineStart(src, i) && i < len(b) && b[i] == '=' && isLetter(byteAt(src, i+1)) {
			end := findPodEnd(src, i)
			blank(i, end)
			i = end
			continue
		}
		matched := false
		for _, pre := range spec.LineComments {
			if strings.HasPrefix(src[i:], pre) {
				end := strings.IndexByte(src[i:], '\n')
				if end < 0 {
					end = len(src) - i
				}
				blank(i, i+end)
				i += end
				matched = true
				break
			}
		}
		if matched {
			continue
		}
		for _, pair := range spec.BlockComments {
			if strings.HasPrefix(src[i:], pair[0]) {
				rest := strings.Index(src[i+len(pair[0]):], pair[1])
				end := len(src)
				if rest >= 0 {
					end = i + len(pair[0]) + rest + len(pair[1])
				}
				blank(i, end)
				i = end
				matched = true
				break
			}
		}
		if matched {
			continue
		}
		i++
	}
	return string(b)
}

func findPodEnd(src string, start int) int {
	// A POD block runs until a line beginning "=cut", inclusive.
	rest := src[start:]
	for off := 0; ; {
		nl := strings.IndexByte(rest[off:], '\n')
		lineEnd := len(rest)
		if nl >= 0 {
			lineEnd = off + nl + 1
		}
		line := rest[off:lineEnd]
		if strings.HasPrefix(line, "=cut") {
			return start + lineEnd
		}
		if nl < 0 {
			return len(src)
		}
		off = lineEnd
	}
}

// skipStringLiteral advances past a string literal starting at i. It returns the
// offset after the literal and whether one was found.
func skipStringLiteral(src string, i int, spec *Spec) (int, bool) {
	_, _, end, ok := scanString(src, i, spec)
	if !ok {
		return i, false
	}
	return end, true
}

// strPart is one piece of a parsed string literal: either literal text or an
// interpolated expression's source.
type strPart struct {
	text   string
	expr   string
	isExpr bool
}

// scanString parses a string literal starting at i, returning its parts, the
// syntax that matched, and the offset just past the closing delimiter.
func scanString(src string, i int, spec *Spec) ([]strPart, *StringSyntax, int, bool) {
	for si := range spec.Strings {
		syn := &spec.Strings[si]
		start := i
		if syn.Prefix != "" {
			if !strings.HasPrefix(src[i:], syn.Prefix+syn.Open) {
				continue
			}
			start = i + len(syn.Prefix)
		} else if !strings.HasPrefix(src[i:], syn.Open) {
			continue
		} else if hasStringPrefixChar(src, i, spec) {
			// A prefixed form such as f"..." must win over the bare form, so
			// skip the bare match when a known prefix precedes the quote.
			continue
		}
		parts, end, ok := scanStringBody(src, start+len(syn.Open), syn)
		if !ok {
			continue
		}
		return parts, syn, end, true
	}
	return nil, nil, i, false
}

// hasStringPrefixChar reports whether the byte before i is a string prefix
// character declared by some syntax in the spec.
func hasStringPrefixChar(src string, i int, spec *Spec) bool {
	if i == 0 {
		return false
	}
	prev := src[i-1]
	for _, syn := range spec.Strings {
		if syn.Prefix != "" && len(syn.Prefix) == 1 && syn.Prefix[0] == prev {
			// Only treat it as a prefix when it is not part of a longer word,
			// so a variable named "conf" before a quote is not mistaken for one.
			if i >= 2 && (isLetter(src[i-2]) || isDigit(src[i-2]) || src[i-2] == '_') {
				return false
			}
			return true
		}
	}
	return false
}

func scanStringBody(src string, i int, syn *StringSyntax) ([]strPart, int, bool) {
	var parts []strPart
	var lit strings.Builder
	flush := func() {
		if lit.Len() > 0 {
			parts = append(parts, strPart{text: lit.String()})
			lit.Reset()
		}
	}
	for i < len(src) {
		if !syn.NoEscapes && src[i] == '\\' && i+1 < len(src) {
			lit.WriteString(unescape(src[i : i+2]))
			i += 2
			continue
		}
		if strings.HasPrefix(src[i:], syn.Close) {
			// A verbatim string escapes its delimiter by doubling it.
			if syn.NoEscapes && strings.HasPrefix(src[i:], syn.Close+syn.Close) {
				lit.WriteString(syn.Close)
				i += 2 * len(syn.Close)
				continue
			}
			flush()
			return parts, i + len(syn.Close), true
		}
		if adv, expr, ok := matchInterp(src, i, syn); ok {
			flush()
			parts = append(parts, strPart{expr: expr, isExpr: true})
			i = adv
			continue
		}
		lit.WriteByte(src[i])
		i++
	}
	// Unterminated literal: treat what we have as the value rather than
	// discarding a call site over a syntax error elsewhere in the file.
	flush()
	return parts, len(src), len(parts) > 0
}

// matchInterp recognizes an interpolation at i, returning the expression source
// and the offset after it.
func matchInterp(src string, i int, syn *StringSyntax) (int, string, bool) {
	for _, in := range syn.Interp {
		if !strings.HasPrefix(src[i:], in.Open) {
			continue
		}
		depth := 0
		j := i + len(in.Open)
		for j < len(src) {
			switch {
			case strings.HasPrefix(src[j:], in.Open) && in.Open != in.Close:
				depth++
				j += len(in.Open)
			case strings.HasPrefix(src[j:], in.Close):
				if depth == 0 {
					return j + len(in.Close), src[i+len(in.Open) : j], true
				}
				depth--
				j += len(in.Close)
			default:
				j++
			}
		}
		return len(src), src[i+len(in.Open):], true
	}
	// A bare sigil variable, as in Perl's "$base/path" or "@{[expr]}".
	if syn.BareSigils != "" && strings.IndexByte(syn.BareSigils, src[i]) >= 0 {
		j := i + 1
		if j < len(src) && src[j] == '{' {
			if k := strings.IndexByte(src[j:], '}'); k >= 0 {
				return j + k + 1, src[j+1 : j+k], true
			}
		}
		for j < len(src) && (isLetter(src[j]) || isDigit(src[j]) || src[j] == '_') {
			j++
		}
		// Allow one level of member access: "$self->{base}" and "$cfg.base".
		for j < len(src) && (src[j] == '-' && byteAt(src, j+1) == '>' || src[j] == '.') {
			k := j
			if src[j] == '-' {
				k = j + 2
			} else {
				k = j + 1
			}
			if k < len(src) && src[k] == '{' {
				if e := strings.IndexByte(src[k:], '}'); e >= 0 {
					j = k + e + 1
					continue
				}
			}
			start := k
			for k < len(src) && (isLetter(src[k]) || isDigit(src[k]) || src[k] == '_') {
				k++
			}
			if k == start {
				break
			}
			j = k
		}
		if j > i+1 {
			return j, src[i:j], true
		}
	}
	return i, "", false
}

func unescape(pair string) string {
	if len(pair) != 2 {
		return pair
	}
	switch pair[1] {
	case 'n':
		return "\n"
	case 't':
		return "\t"
	case 'r':
		return "\r"
	case '0':
		return "\x00"
	default:
		return string(pair[1])
	}
}

// sliceArgs reads a balanced argument list starting at the "(" at open. It
// tracks bracket depth and string state, so it crosses newlines correctly and
// is not fooled by commas, parentheses or braces inside string literals.
func sliceArgs(src string, open int, spec *Spec) ([]string, int, bool) {
	if open >= len(src) || src[open] != '(' {
		return nil, open, false
	}
	var args []string
	depth := 0
	start := open + 1
	i := open
	for i < len(src) {
		if adv, ok := skipStringLiteral(src, i, spec); ok && adv > i {
			i = adv
			continue
		}
		switch src[i] {
		case '(', '[', '{':
			depth++
			i++
		case ')', ']', '}':
			depth--
			if depth == 0 {
				args = appendArg(args, src[start:i])
				return args, i + 1, true
			}
			i++
		case ',':
			if depth == 1 {
				args = appendArg(args, src[start:i])
				start = i + 1
			}
			i++
		case '=':
			// Perl's fat comma is a comma. Only "=>" counts; "==" and ">=" must
			// not split an argument.
			if spec.FatComma && depth == 1 && byteAt(src, i+1) == '>' {
				args = appendArg(args, src[start:i])
				start = i + 2
				i += 2
				continue
			}
			i++
		default:
			i++
		}
	}
	// Unbalanced: give back what we read rather than losing the call.
	if start < len(src) {
		args = appendArg(args, src[start:])
	}
	return args, len(src), len(args) > 0
}

func appendArg(args []string, s string) []string {
	s = strings.TrimSpace(s)
	if s == "" && len(args) == 0 {
		return args
	}
	return append(args, s)
}

// isObjectLiteral reports whether an argument is an object or hash literal.
func isObjectLiteral(arg string) bool {
	t := strings.TrimSpace(arg)
	return strings.HasPrefix(t, "{") || strings.HasPrefix(t, "new ") ||
		strings.Contains(t, "=>") || strings.Contains(t, ": ")
}

// objectValue extracts a key's value from an object, hash or named-argument
// list. It handles JS "{url: x}", Ruby and Perl "url => x", Python "url=x" and
// C# "RequestUri = x" with one scanner, because they differ only in separator.
func objectValue(arg, key string, spec *Spec) (string, bool) {
	body := strings.TrimSpace(arg)
	body = strings.TrimPrefix(body, "{")
	body = strings.TrimSuffix(body, "}")
	fields := splitTopLevel(body, ',', spec)
	for _, f := range fields {
		f = strings.TrimSpace(f)
		for _, sep := range []string{"=>", ":", "="} {
			k, v, ok := strings.Cut(f, sep)
			if !ok {
				continue
			}
			k = strings.Trim(strings.TrimSpace(k), `"'`)
			if !strings.EqualFold(k, key) {
				continue
			}
			if v = strings.TrimSpace(v); v != "" {
				return v, true
			}
		}
	}
	return "", false
}

// splitTopLevel splits on sep at bracket depth zero, ignoring separators inside
// strings.
func splitTopLevel(s string, sep byte, spec *Spec) []string {
	var out []string
	depth, start := 0, 0
	for i := 0; i < len(s); {
		if adv, ok := skipStringLiteral(s, i, spec); ok && adv > i {
			i = adv
			continue
		}
		switch s[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case sep:
			if depth == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
		i++
	}
	out = append(out, s[start:])
	return out
}

func indexAtLineStart(src, marker string) int {
	if strings.HasPrefix(src, marker) {
		return 0
	}
	if i := strings.Index(src, "\n"+marker); i >= 0 {
		return i + 1
	}
	return -1
}

func atLineStart(src string, i int) bool {
	return i == 0 || src[i-1] == '\n'
}

// onlySpaceBeforeOnLine reports whether only whitespace precedes i on its line,
// which is what distinguishes a docstring statement from a string being
// assigned to a variable.
func onlySpaceBeforeOnLine(src string, i int) bool {
	for j := i - 1; j >= 0; j-- {
		switch src[j] {
		case '\n':
			return true
		case ' ', '\t', '\r':
		default:
			return false
		}
	}
	return true
}

func byteAt(s string, i int) byte {
	if i < 0 || i >= len(s) {
		return 0
	}
	return s[i]
}

func isLetter(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
