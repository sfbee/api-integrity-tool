package walk

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
)

// Skip reasons recorded in Stats.Skipped.
const (
	SkipExcluded   = "excluded"
	SkipIgnored    = "gitignored"
	SkipTooLarge   = "too_large"
	SkipBinary     = "binary"
	SkipMinified   = "minified"
	SkipUnknownExt = "unknown_extension"
	SkipUnreadable = "unreadable"
	SkipSymlink    = "symlink"
	SkipNotMatched = "path_glob"
)

// DefaultMaxFileSize is the per-file cap. Two megabytes is far larger than any
// hand-written source file; beyond it we are reading generated data.
const DefaultMaxFileSize = 2 << 20

// maxLineLength above which a file is treated as minified. A 2000-byte line is a
// robust minification signal and much more reliable than trusting a ".min.js"
// suffix alone.
const maxLineLength = 2000

// Candidate is a file worth handing to a detector.
type Candidate struct {
	RelPath string
	AbsPath string
	Size    int64
	Ext     string
	// Interp is the interpreter named in the file's shebang, set only when the
	// file has no extension. Real repositories are full of executable scripts
	// with no suffix -- a repository will keep whole Perl programs that way --
	// and matching on extension alone skips every one of them.
	Interp string
}

// Options configures a walk.
type Options struct {
	Root string
	// Extensions limits traversal to files a detector claims. Empty means all.
	Extensions  map[string]bool
	MaxFileSize int64
	// RespectGitignore honours .gitignore, .git/info/exclude and nested ignore
	// files. On by default because a scan that reports a dependency's calls as
	// yours is worse than useless.
	RespectGitignore bool
	// Shebangs are the interpreter names worth reading, e.g. "perl". A file with
	// no extension is sniffed only when this is non-empty, so the extra I/O is
	// opt-in and bounded to extensionless files.
	Shebangs       map[string]bool
	FollowSymlinks bool
	// ExcludeDirs are directory names pruned before descending, which is what
	// makes a 50k-file repo cheap: node_modules is never entered.
	ExcludeDirs []string
	// ExcludeGlobs and IncludeGlobs are repo-relative path patterns.
	ExcludeGlobs []string
	IncludeGlobs []string
	PathGlobs    []string
}

// Stats counts what the walk did and, importantly, what it declined to do.
type Stats struct {
	Walked  int
	Matched int
	Skipped map[string]int
	Bytes   int64
}

func (s *Stats) skip(reason string) {
	if s.Skipped == nil {
		s.Skipped = map[string]int{}
	}
	s.Skipped[reason]++
}

// Find walks root and returns the candidate files in deterministic order.
//
// Directory-level pruning happens before descending, and the result is sorted,
// so the output does not depend on filesystem iteration order -- a
// precondition for byte-identical golden files.
func Find(ctx context.Context, opts Options) ([]Candidate, Stats, error) {
	var stats Stats
	root, err := filepath.Abs(opts.Root)
	if err != nil {
		return nil, stats, fmt.Errorf("resolve %s: %w", opts.Root, err)
	}
	info, err := os.Stat(root)
	if err != nil {
		return nil, stats, fmt.Errorf("stat %s: %w", root, err)
	}
	if !info.IsDir() {
		return nil, stats, fmt.Errorf("%s is not a directory", root)
	}

	maxSize := opts.MaxFileSize
	if maxSize <= 0 {
		maxSize = DefaultMaxFileSize
	}
	excludeDirs := make(map[string]bool, len(opts.ExcludeDirs))
	for _, d := range opts.ExcludeDirs {
		excludeDirs[d] = true
	}

	// Ignore stacks are keyed by repo-relative directory. A child inherits its
	// parent's stack plus its own .gitignore.
	stacks := map[string]*IgnoreStack{}
	base := &IgnoreStack{}
	if opts.RespectGitignore {
		_ = base.AddFile(filepath.Join(root, ".gitignore"), "")
		_ = base.AddFile(filepath.Join(root, ".git", "info", "exclude"), "")
	}
	stacks["."] = base

	var out []Candidate
	walkFn := func(p string, d fs.DirEntry, err error) error {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if err != nil {
			// An unreadable directory is reported and skipped, never fatal.
			stats.skip(SkipUnreadable)
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		rel, relErr := filepath.Rel(root, p)
		if relErr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}

		if d.Type()&os.ModeSymlink != 0 {
			// Symlinks are not followed by default: a link out of the repo would
			// index files that are not ours, and a cycle would never terminate.
			if !opts.FollowSymlinks {
				stats.skip(SkipSymlink)
				return nil
			}
		}

		parent := path.Dir(rel)
		stack := stacks[parent]
		if stack == nil {
			stack = base
		}

		if d.IsDir() {
			if excludeDirs[d.Name()] || strings.HasPrefix(d.Name(), ".") && excludeDirs[d.Name()] {
				stats.skip(SkipExcluded)
				return fs.SkipDir
			}
			if matchAnyGlob(rel, opts.ExcludeGlobs) && !matchAnyGlob(rel, opts.IncludeGlobs) {
				stats.skip(SkipExcluded)
				return fs.SkipDir
			}
			if opts.RespectGitignore && stack.Match(rel, true) && !matchAnyGlob(rel, opts.IncludeGlobs) {
				stats.skip(SkipIgnored)
				return fs.SkipDir
			}
			child := stack.Clone()
			if opts.RespectGitignore {
				_ = child.AddFile(filepath.Join(p, ".gitignore"), rel)
			}
			stacks[rel] = child
			return nil
		}

		stats.Walked++
		included := matchAnyGlob(rel, opts.IncludeGlobs)
		if matchAnyGlob(rel, opts.ExcludeGlobs) && !included {
			stats.skip(SkipExcluded)
			return nil
		}
		if opts.RespectGitignore && stack.Match(rel, false) && !included {
			stats.skip(SkipIgnored)
			return nil
		}
		if len(opts.PathGlobs) > 0 && !matchAnyGlob(rel, opts.PathGlobs) {
			stats.skip(SkipNotMatched)
			return nil
		}
		ext := strings.ToLower(path.Ext(rel))
		interp := ""
		if len(opts.Extensions) > 0 && !opts.Extensions[ext] {
			// An extensionless file may still be a script. Only such files are
			// sniffed: reading the head of every .md and .txt would cost real
			// I/O for nothing.
			if ext != "" || len(opts.Shebangs) == 0 {
				stats.skip(SkipUnknownExt)
				return nil
			}
			interp = ReadShebang(p)
			if interp == "" || !opts.Shebangs[interp] {
				stats.skip(SkipUnknownExt)
				return nil
			}
		}
		fi, statErr := d.Info()
		if statErr != nil {
			stats.skip(SkipUnreadable)
			return nil
		}
		if fi.Size() > maxSize {
			stats.skip(SkipTooLarge)
			return nil
		}
		out = append(out, Candidate{RelPath: rel, AbsPath: p, Size: fi.Size(), Ext: ext, Interp: interp})
		stats.Matched++
		stats.Bytes += fi.Size()
		return nil
	}

	if err := filepath.WalkDir(root, walkFn); err != nil {
		return nil, stats, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RelPath < out[j].RelPath })
	return out, stats, nil
}

func matchAnyGlob(rel string, globs []string) bool {
	for _, g := range globs {
		if g == "" {
			continue
		}
		if ok, _ := path.Match(g, rel); ok {
			return true
		}
		// A directory prefix pattern matches everything beneath it.
		trimmed := strings.TrimSuffix(strings.TrimSuffix(g, "/**"), "/")
		if trimmed != "" && (rel == trimmed || strings.HasPrefix(rel, trimmed+"/")) {
			return true
		}
		if ok, _ := path.Match(g, path.Base(rel)); ok && !strings.Contains(g, "/") {
			return true
		}
	}
	return false
}

// shebangBytes is how much of a file is read to find its interpreter. A shebang
// is the first line by definition, so this is generous.
const shebangBytes = 128

// ReadShebang returns the normalized interpreter name from a file's shebang, or
// "" when there is none. It handles the direct form ("#!/usr/bin/perl"), the
// env form ("#!/usr/bin/env python3"), trailing flags ("#!/usr/bin/perl -w")
// and version suffixes ("python3" -> "python").
func ReadShebang(absPath string) string {
	f, err := os.Open(absPath)
	if err != nil {
		return ""
	}
	defer f.Close()
	buf := make([]byte, shebangBytes)
	n, _ := f.Read(buf)
	if n < 3 || buf[0] != '#' || buf[1] != '!' {
		return ""
	}
	line := string(buf[2:n])
	if i := strings.IndexAny(line, "\r\n"); i >= 0 {
		line = line[:i]
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return ""
	}
	interp := path.Base(fields[0])
	// "env perl" and "env -S perl -w": the real interpreter is the first field
	// that is not a flag.
	if interp == "env" {
		interp = ""
		for _, f := range fields[1:] {
			if strings.HasPrefix(f, "-") || strings.Contains(f, "=") {
				continue
			}
			interp = path.Base(f)
			break
		}
		if interp == "" {
			return ""
		}
	}
	return NormalizeInterpreter(interp)
}

// knownInterpreters are the base names NormalizeInterpreter resolves to.
var knownInterpreters = []string{"perl", "python", "ruby", "node"}

// NormalizeInterpreter reduces an interpreter binary name to a bare language
// name. It strips a trailing version ("python3.11" -> "python") and a vendor
// prefix ("vendor-perl" -> "perl"), because distributions rename interpreters
// freely: a vendor that ships its own build as /usr/bin/vendor-perl would
// otherwise have every one of its scripts skipped, since the shebang never
// names "perl" on its own.
func NormalizeInterpreter(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	name = strings.TrimSuffix(name, ".exe")
	if trimmed := strings.TrimRight(name, "0123456789."); trimmed != "" {
		name = trimmed
	}
	if name == "nodejs" {
		return "node"
	}
	for _, known := range knownInterpreters {
		if name == known {
			return known
		}
	}
	// A vendor-prefixed or -suffixed build: take the component that names a
	// language, e.g. "vendor-perl", "perl-static", "vendor-php-python".
	for _, part := range strings.FieldsFunc(name, func(r rune) bool { return r == '-' || r == '_' }) {
		part = strings.TrimRight(part, "0123456789.")
		for _, known := range knownInterpreters {
			if part == known {
				return known
			}
		}
	}
	return name
}

// ContentSkipReason inspects file content for reasons a detector should not see
// it. These checks need the bytes, so they run in the reading worker rather
// than during traversal.
func ContentSkipReason(content []byte) string {
	head := content
	if len(head) > 8192 {
		head = head[:8192]
	}
	if isBinary(head) {
		return SkipBinary
	}
	if longestLine(content) > maxLineLength {
		return SkipMinified
	}
	return ""
}

// magicPrefixes short-circuit the heuristic for common binary formats.
var magicPrefixes = [][]byte{
	{0x7f, 'E', 'L', 'F'},
	{0xcf, 0xfa, 0xed, 0xfe},
	{0xfe, 0xed, 0xfa, 0xce},
	{'M', 'Z'},
	{0x89, 'P', 'N', 'G'},
	{0xff, 0xd8, 0xff},
	{0x1f, 0x8b},
	{'P', 'K', 0x03, 0x04},
	{'%', 'P', 'D', 'F'},
	{0xca, 0xfe, 0xba, 0xbe},
}

func isBinary(head []byte) bool {
	for _, m := range magicPrefixes {
		if len(head) >= len(m) && string(head[:len(m)]) == string(m) {
			return true
		}
	}
	for _, b := range head {
		if b == 0 {
			return true
		}
	}
	// Trim a possibly-truncated final rune before validating.
	trimmed := head
	for len(trimmed) > 0 && !utf8.Valid(trimmed) && len(head)-len(trimmed) < 4 {
		trimmed = trimmed[:len(trimmed)-1]
	}
	if !utf8.Valid(trimmed) {
		return true
	}
	var nonPrintable int
	for _, b := range head {
		if b < 0x09 || (b > 0x0d && b < 0x20) {
			nonPrintable++
		}
	}
	return len(head) > 0 && nonPrintable*100/len(head) > 30
}

func longestLine(content []byte) int {
	longest, cur := 0, 0
	for _, b := range content {
		if b == '\n' {
			if cur > longest {
				longest = cur
			}
			cur = 0
			continue
		}
		cur++
	}
	if cur > longest {
		longest = cur
	}
	return longest
}

// generatedMarkers appear in the first few lines of machine-written files.
var generatedMarkers = []string{
	"Code generated by", "DO NOT EDIT", "<auto-generated", "@generated",
	"autogenerated", "This file was automatically generated",
}

// IsGenerated reports whether content looks machine-written. Generated files are
// indexed but scored lower: their calls are real, but nobody maintains them by
// hand and a change there means the generator changed.
func IsGenerated(content []byte) bool {
	head := content
	if len(head) > 4096 {
		head = head[:4096]
	}
	s := string(head)
	for _, m := range generatedMarkers {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}
