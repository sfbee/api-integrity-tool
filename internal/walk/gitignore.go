// Package walk finds candidate source files in a repository.
package walk

import (
	"bufio"
	"os"
	"path"
	"regexp"
	"strings"
)

// ignorePattern is one compiled .gitignore line.
type ignorePattern struct {
	// exact matches the named entry itself; under matches anything beneath it.
	// Both are needed for directory-only patterns: "build/" must not match a
	// *file* called "build", but must match "build/out.txt", because that file
	// lives inside an ignored directory.
	exact   *regexp.Regexp
	under   *regexp.Regexp
	negate  bool
	dirOnly bool
	// base is the directory the pattern was declared in, repo-relative with no
	// leading slash. Matching is always done against paths under base.
	base string
	raw  string
}

// IgnoreStack holds the .gitignore patterns in effect, ordered outermost first.
// A stack rather than a flat list because a nested .gitignore can re-include
// something its parent excluded, and the last matching pattern wins.
type IgnoreStack struct {
	patterns []ignorePattern
}

// Clone returns a copy so a child directory can extend the stack without
// mutating its parent's view.
func (s *IgnoreStack) Clone() *IgnoreStack {
	if s == nil {
		return &IgnoreStack{}
	}
	out := &IgnoreStack{patterns: make([]ignorePattern, len(s.patterns))}
	copy(out.patterns, s.patterns)
	return out
}

// AddFile parses a .gitignore located in the repo-relative directory base.
// A missing file is not an error.
func (s *IgnoreStack) AddFile(absPath, base string) error {
	f, err := os.Open(absPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		s.AddLine(sc.Text(), base)
	}
	return sc.Err()
}

// AddLine compiles one .gitignore line.
func (s *IgnoreStack) AddLine(line, base string) {
	raw := line
	// Trailing spaces are insignificant unless escaped.
	if !strings.HasSuffix(line, "\\ ") {
		line = strings.TrimRight(line, " ")
	}
	if line == "" || strings.HasPrefix(line, "#") {
		return
	}
	p := ignorePattern{base: strings.Trim(base, "/"), raw: raw}
	if strings.HasPrefix(line, "!") {
		p.negate = true
		line = line[1:]
	}
	if strings.HasSuffix(line, "/") {
		p.dirOnly = true
		line = strings.TrimSuffix(line, "/")
	}
	if line == "" {
		return
	}
	// A pattern containing a slash anywhere but the end is anchored to the
	// directory holding the .gitignore; otherwise it matches at any depth.
	anchored := strings.Contains(line, "/")
	line = strings.TrimPrefix(line, "/")

	exact, under, err := compileGlob(line, anchored)
	if err != nil {
		return
	}
	p.exact, p.under = exact, under
	s.patterns = append(s.patterns, p)
}

// compileGlob converts a gitignore glob into two regexps: one matching the
// named entry, one matching everything beneath it.
func compileGlob(glob string, anchored bool) (exact, under *regexp.Regexp, err error) {
	var b strings.Builder
	b.WriteString(`^`)
	if !anchored {
		// Unanchored patterns match at any depth.
		b.WriteString(`(?:.*/)?`)
	}
	for i := 0; i < len(glob); i++ {
		c := glob[i]
		switch c {
		case '*':
			if i+1 < len(glob) && glob[i+1] == '*' {
				// "**" spans directories. Consume an adjacent slash so
				// "a/**/b" also matches "a/b".
				i++
				if i+1 < len(glob) && glob[i+1] == '/' {
					i++
					b.WriteString(`(?:.*/)?`)
				} else {
					b.WriteString(`.*`)
				}
				continue
			}
			b.WriteString(`[^/]*`)
		case '?':
			b.WriteString(`[^/]`)
		case '[':
			j := i + 1
			if j < len(glob) && (glob[j] == '!' || glob[j] == '^') {
				j++
			}
			for j < len(glob) && glob[j] != ']' {
				j++
			}
			if j >= len(glob) {
				b.WriteString(regexp.QuoteMeta("["))
				continue
			}
			cls := glob[i+1 : j]
			if strings.HasPrefix(cls, "!") {
				cls = "^" + cls[1:]
			}
			b.WriteString("[" + cls + "]")
			i = j
		case '\\':
			if i+1 < len(glob) {
				i++
				b.WriteString(regexp.QuoteMeta(string(glob[i])))
			}
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	body := b.String()
	if exact, err = regexp.Compile(body + `$`); err != nil {
		return nil, nil, err
	}
	if under, err = regexp.Compile(body + `/.*$`); err != nil {
		return nil, nil, err
	}
	return exact, under, nil
}

// Match reports whether rel (a repo-relative, slash-separated path) is ignored.
// isDir affects directory-only patterns. The last matching pattern wins, which
// is what makes negation work.
func (s *IgnoreStack) Match(rel string, isDir bool) bool {
	if s == nil {
		return false
	}
	rel = strings.Trim(rel, "/")
	ignored := false
	for i := range s.patterns {
		p := &s.patterns[i]
		sub := rel
		if p.base != "" {
			if !strings.HasPrefix(rel, p.base+"/") {
				continue
			}
			sub = rel[len(p.base)+1:]
		}
		switch {
		case p.under.MatchString(sub):
			// The path is inside the matched entry, so that entry is a
			// directory whatever the pattern demanded.
			ignored = !p.negate
		case p.exact.MatchString(sub) && (isDir || !p.dirOnly):
			ignored = !p.negate
		}
	}
	return ignored
}

// Len reports how many patterns are loaded, for diagnostics.
func (s *IgnoreStack) Len() int {
	if s == nil {
		return 0
	}
	return len(s.patterns)
}

// ToSlash normalizes an OS path to the forward-slash form used everywhere in
// the index. Absolute paths must never reach the index, so every path passes
// through here on its way in.
func ToSlash(p string) string { return path.Clean(strings.ReplaceAll(p, `\`, "/")) }
