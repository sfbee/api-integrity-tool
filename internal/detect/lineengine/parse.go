package lineengine

import (
	"strings"

	"github.com/stephen-bee/endpoint-monitor/internal/detect"
)

// parseExpr translates one argument's source text into the shared IR.
//
// It recognizes exactly the constructs that build URLs -- string literals with
// interpolation, concatenation, format calls, path joins, environment reads and
// subscripts -- and yields an opaque node for everything else. An opaque node
// becomes a hole downstream, which reports honestly that we could not read the
// expression instead of inventing a URL.
func (d Detector) parseExpr(text string) *detect.Expr {
	return d.parseExprDepth(text, 0)
}

// maxParseDepth bounds recursion through nested calls and concatenations.
const maxParseDepth = 12

func (d Detector) parseExprDepth(text string, depth int) *detect.Expr {
	t := strings.TrimSpace(text)
	if t == "" {
		return nil
	}
	if depth > maxParseDepth {
		return detect.Unknown(t)
	}
	t = unwrapParens(t, d.spec)

	// A whole-string literal, possibly with interpolation.
	if parts, _, end, ok := scanString(t, 0, d.spec); ok && end == len(t) {
		return d.stringExpr(parts, t, depth)
	}

	// Top-level concatenation. Checked before calls so "f(x) + \"/y\"" splits
	// correctly rather than being read as one opaque call.
	for _, op := range d.spec.ConcatOps {
		if pieces := splitTopLevelOp(t, op, d.spec); len(pieces) > 1 {
			exprs := make([]*detect.Expr, 0, len(pieces))
			for _, p := range pieces {
				exprs = append(exprs, d.parseExprDepth(p, depth+1))
			}
			return detect.Concat(exprs...)
		}
	}

	// An environment variable read.
	for _, re := range d.spec.EnvRe {
		if loc := re.FindStringSubmatchIndex(t); loc != nil && loc[0] == 0 && loc[1] == len(t) {
			if name := submatchAt(re, t, loc, "name"); name != "" {
				return detect.Env(strings.Trim(name, `"'`), nil)
			}
		}
	}

	// A call: format, join, or something opaque but named.
	if callee, args, ok := splitCall(t, d.spec); ok {
		return d.callExpr(callee, args, t, depth)
	}

	// A subscript, such as config["api"]["base"].
	if base, key, ok := splitSubscript(t, d.spec); ok {
		return detect.Index(d.parseExprDepth(base, depth+1), d.parseExprDepth(key, depth+1))
	}

	if isIdentifierPath(t) {
		return detect.Sym(d.qualifySelf(normalizeIdent(t, d.spec)))
	}
	return detect.Unknown(t)
}

// stringExpr turns parsed string parts into a literal or a template.
func (d Detector) stringExpr(parts []strPart, src string, depth int) *detect.Expr {
	if len(parts) == 0 {
		return detect.Lit("")
	}
	if len(parts) == 1 && !parts[0].isExpr {
		return detect.Lit(parts[0].text)
	}
	pieces := make([]*detect.Expr, 0, len(parts))
	for _, p := range parts {
		if !p.isExpr {
			pieces = append(pieces, detect.Lit(p.text))
			continue
		}
		e := d.parseExprDepth(p.expr, depth+1)
		if e == nil {
			e = detect.Unknown(p.expr)
		}
		pieces = append(pieces, e)
	}
	out := detect.Template(pieces...)
	out.Src = detect.TrimSrc(src)
	return out
}

func (d Detector) callExpr(callee string, args []string, src string, depth int) *detect.Expr {
	short := lastComponent(callee)

	// A format call: the first argument is the template, the rest are values.
	for _, name := range d.spec.FormatCalls {
		if !strings.EqualFold(short, name) {
			continue
		}
		// "template".format(a, b) puts the template in the receiver instead.
		if base, ok := formatReceiver(callee, name); ok {
			if parts, _, end, ok := scanString(base, 0, d.spec); ok && end == len(base) {
				return d.formatFromParts(parts, args, depth)
			}
		}
		if len(args) >= 1 {
			if parts, _, end, ok := scanString(args[0], 0, d.spec); ok && end == len(args[0]) {
				return d.formatFromParts(parts, args[1:], depth)
			}
		}
		return detect.Call(short, d.parseArgs(args, depth)...)
	}

	for _, name := range d.spec.JoinCalls {
		if strings.EqualFold(short, name) {
			// A receiver-style join, "base.join(a, b)", includes the receiver.
			if base, ok := formatReceiver(callee, name); ok && base != "" {
				return detect.Join(append([]*detect.Expr{d.parseExprDepth(base, depth+1)}, d.parseArgs(args, depth)...)...)
			}
			return detect.Join(d.parseArgs(args, depth)...)
		}
	}

	// Escaping and trimming helpers do not change which endpoint is addressed.
	switch strings.ToLower(short) {
	case "encodeuricomponent", "encodeuri", "quote", "quote_plus", "urlencode",
		"escape", "pathescape", "strip", "trim", "rstrip", "chomp", "tostring", "to_s", "str",
		// Wrappers that carry a URL without changing it: URI.create(s),
		// new Uri(s), HttpUrl.parse(s), URI->new(s), URI(s). "new" is broad,
		// but parseExpr is only ever called on a URL or method argument
		// position, where a constructor is virtually always wrapping the URL.
		"create", "parse", "uri", "url", "valueof", "fromhttpurl", "newinstance", "new":
		if len(args) == 1 {
			return d.parseExprDepth(args[0], depth+1)
		}
		if len(args) == 0 {
			if base, ok := formatReceiver(callee, short); ok && base != "" {
				return d.parseExprDepth(base, depth+1)
			}
		}
	}

	return detect.Call(short, d.parseArgs(args, depth)...)
}

// formatFromParts converts an already-parsed template string plus its arguments
// into a format expression, preserving any interpolations the string itself had.
func (d Detector) formatFromParts(parts []strPart, args []string, depth int) *detect.Expr {
	var sb strings.Builder
	var inline []*detect.Expr
	for _, p := range parts {
		if p.isExpr {
			// An interpolation inside a format string is already a value; give
			// it a positional slot so ordering with the real arguments holds.
			sb.WriteString("%s")
			inline = append(inline, d.parseExprDepth(p.expr, depth+1))
			continue
		}
		sb.WriteString(p.text)
	}
	all := append(inline, d.parseArgs(args, depth)...)
	return detect.Format(sb.String(), all...)
}

func (d Detector) parseArgs(args []string, depth int) []*detect.Expr {
	out := make([]*detect.Expr, 0, len(args))
	for _, a := range args {
		if e := d.parseExprDepth(a, depth+1); e != nil {
			out = append(out, e)
		}
	}
	return out
}

// splitCall separates "name(args...)" into its callee and argument list. It
// requires the closing parenthesis to be the last character, so a concatenation
// containing a call is not mistaken for a single call.
func splitCall(t string, spec *Spec) (string, []string, bool) {
	if !strings.HasSuffix(t, ")") {
		return "", nil, false
	}
	open := -1
	depth := 0
	for i := 0; i < len(t); {
		if adv, ok := skipStringLiteral(t, i, spec); ok && adv > i {
			i = adv
			continue
		}
		switch t[i] {
		case '(':
			if depth == 0 && open < 0 {
				open = i
			}
			depth++
		case ')':
			depth--
		}
		i++
	}
	if open <= 0 {
		return "", nil, false
	}
	args, end, ok := sliceArgs(t, open, spec)
	if !ok || end != len(t) {
		return "", nil, false
	}
	callee := strings.TrimSpace(t[:open])
	if callee == "" {
		return "", nil, false
	}
	return callee, args, true
}

// splitSubscript separates "base[key]" into its parts.
func splitSubscript(t string, spec *Spec) (string, string, bool) {
	if !strings.HasSuffix(t, "]") {
		return "", "", false
	}
	depth := 0
	for i := len(t) - 1; i >= 0; i-- {
		switch t[i] {
		case ']':
			depth++
		case '[':
			depth--
			if depth == 0 {
				if i == 0 {
					return "", "", false
				}
				return strings.TrimSpace(t[:i]), strings.TrimSpace(t[i+1 : len(t)-1]), true
			}
		}
	}
	return "", "", false
}

// splitTopLevelOp splits on an operator at bracket depth zero, outside strings.
// It returns a single-element slice when the operator does not appear, so
// callers can test len() > 1.
func splitTopLevelOp(t, op string, spec *Spec) []string {
	var out []string
	depth, start := 0, 0
	for i := 0; i < len(t); {
		if adv, ok := skipStringLiteral(t, i, spec); ok && adv > i {
			i = adv
			continue
		}
		switch t[i] {
		case '(', '[', '{':
			depth++
			i++
			continue
		case ')', ']', '}':
			depth--
			i++
			continue
		}
		if depth == 0 && strings.HasPrefix(t[i:], op) && !partOfLongerOperator(t, i, op) {
			out = append(out, t[start:i])
			i += len(op)
			start = i
			continue
		}
		i++
	}
	if len(out) == 0 {
		return []string{t}
	}
	return append(out, t[start:])
}

// partOfLongerOperator avoids splitting "+=" or "++" as concatenation, and
// avoids treating a decimal point or a namespace separator as Perl's ".".
func partOfLongerOperator(t string, i int, op string) bool {
	next := byteAt(t, i+len(op))
	prev := byteAt(t, i-1)
	if next == '=' || next == op[0] {
		return true
	}
	if op == "." {
		// A dot between identifier characters is member access, not concatenation.
		if (isLetter(prev) || isDigit(prev) || prev == '_' || prev == '}' || prev == ')') &&
			(isLetter(next) || isDigit(next) || next == '_') {
			return true
		}
		if isDigit(prev) && isDigit(next) {
			return true
		}
	}
	return false
}

func unwrapParens(t string, spec *Spec) string {
	for strings.HasPrefix(t, "(") && strings.HasSuffix(t, ")") {
		inner := t[1 : len(t)-1]
		if !balanced(inner, spec) {
			return t
		}
		t = strings.TrimSpace(inner)
	}
	return t
}

func balanced(s string, spec *Spec) bool {
	depth := 0
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
			if depth < 0 {
				return false
			}
		}
		i++
	}
	return depth == 0
}

// formatReceiver returns the receiver of a method-style call: for
// "\"x/{}\".format" with name "format" it returns the quoted template.
func formatReceiver(callee, name string) (string, bool) {
	lower := strings.ToLower(callee)
	suffix := "." + strings.ToLower(name)
	if !strings.HasSuffix(lower, suffix) {
		return "", false
	}
	return strings.TrimSpace(callee[:len(callee)-len(suffix)]), true
}

func lastComponent(callee string) string {
	for _, sep := range []string{"->", "::", ".", "!"} {
		if i := strings.LastIndex(callee, sep); i >= 0 {
			callee = callee[i+len(sep):]
		}
	}
	return strings.TrimSpace(callee)
}

// isIdentifierPath reports whether t is a plain (possibly dotted) reference,
// which becomes a symbol lookup rather than an opaque hole.
func isIdentifierPath(t string) bool {
	if t == "" {
		return false
	}
	for i := 0; i < len(t); i++ {
		c := t[i]
		switch {
		case isLetter(c), isDigit(c), c == '_', c == '.', c == '$', c == '@', c == ':', c == '{', c == '}':
		case c == '-' && byteAt(t, i+1) == '>':
			i++
		default:
			return false
		}
	}
	return isLetter(t[0]) || t[0] == '_' || t[0] == '$' || t[0] == '@'
}

// normalizeIdent rewrites a language's self-reference to a stable name so a
// field assignment and a field read agree. Perl's "$self->{base}" and Python's
// "self.base" both become "self.base".
func normalizeIdent(t string, spec *Spec) string {
	t = strings.TrimSpace(t)
	t = strings.ReplaceAll(t, "->{", ".")
	t = strings.ReplaceAll(t, "->", ".")
	t = strings.ReplaceAll(t, "}", "")
	t = strings.TrimPrefix(t, "$")
	t = strings.TrimPrefix(t, "@")
	t = strings.ReplaceAll(t, "::", ".")
	return t
}
