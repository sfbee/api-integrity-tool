// Package analyze holds the individual signals the monitor derives from an
// upstream change.
package analyze

import (
	"path"
	"strings"
)

// Class describes what kind of file a path is, which decides how much weight a
// change to it deserves. A path literal disappearing from a test fixture is not
// evidence that an endpoint was removed.
type Class string

const (
	ClassSpec      Class = "spec"
	ClassRoutes    Class = "routes"
	ClassSource    Class = "source"
	ClassConfig    Class = "config"
	ClassTest      Class = "test"
	ClassDoc       Class = "doc"
	ClassVendor    Class = "vendor"
	ClassGenerated Class = "generated"
	ClassLock      Class = "lock"
	ClassBinary    Class = "binary"
)

// Weight is the multiplier a finding's confidence receives for this class.
func (c Class) Weight() float64 {
	switch c {
	case ClassSpec, ClassRoutes:
		return 1.0
	case ClassSource:
		return 0.9
	case ClassConfig:
		return 0.7
	default:
		return 0.25
	}
}

// CanBreak reports whether a change to this class of file may be classified
// breaking. A removal in a test, a document or a vendored tree may be worth
// mentioning but never justifies the strongest verdict.
func (c Class) CanBreak() bool {
	switch c {
	case ClassSpec, ClassRoutes, ClassSource, ClassConfig:
		return true
	default:
		return false
	}
}

var (
	vendorDirs = []string{
		"vendor/", "node_modules/", "third_party/", "3rdparty/", "external/",
		"site-packages/", ".venv/", "venv/", "target/", "dist/", "build/",
		"Pods/", "Carthage/", ".gradle/",
	}
	testMarkers = []string{
		"/testdata/", "/tests/", "/test/", "/spec/", "/__tests__/", "/cypress/",
		"/e2e/", "/features/", "/fixtures/", "/mocks/", "/__mocks__/",
	}
	docDirs = []string{"docs/", "doc/", "documentation/", "website/", "examples/", "example/"}
)

// Classify decides the class of a repository path.
//
// Ordering matters: a vendored copy of a specification is still vendored, and a
// generated route file is still generated, so those checks come before the more
// specific ones.
func Classify(p string) Class {
	lower := strings.ToLower(strings.TrimPrefix(p, "./"))
	base := path.Base(lower)
	ext := path.Ext(lower)
	slashed := "/" + lower

	for _, d := range vendorDirs {
		if strings.HasPrefix(lower, d) || strings.Contains(slashed, "/"+d) {
			return ClassVendor
		}
	}
	switch {
	case strings.HasSuffix(lower, ".pb.go"), strings.HasSuffix(lower, "_pb2.py"),
		strings.HasSuffix(lower, ".generated.go"), strings.HasSuffix(lower, "_gen.go"),
		strings.HasSuffix(lower, ".g.dart"), strings.HasSuffix(lower, ".designer.cs"),
		strings.Contains(lower, ".generated."):
		return ClassGenerated
	}
	switch {
	case strings.HasSuffix(base, ".lock"), base == "go.sum", base == "package-lock.json",
		base == "yarn.lock", base == "gemfile.lock", base == "poetry.lock",
		base == "pnpm-lock.yaml", base == "cargo.lock", base == "composer.lock":
		return ClassLock
	}
	switch ext {
	case ".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".gz", ".jar", ".class",
		".so", ".dylib", ".dll", ".exe", ".woff", ".woff2", ".ico", ".mp4":
		return ClassBinary
	}

	if IsSpecPath(p) {
		return ClassSpec
	}

	for _, m := range testMarkers {
		if strings.Contains(slashed, m) {
			// A Ruby "spec/" directory is tests, not an API specification.
			return ClassTest
		}
	}
	switch {
	case strings.HasSuffix(lower, "_test.go"), strings.HasSuffix(lower, "_test.py"),
		strings.HasPrefix(base, "test_"), strings.HasSuffix(lower, "_spec.rb"),
		strings.HasSuffix(lower, "_test.rb"), strings.HasSuffix(lower, "test.java"),
		strings.HasSuffix(lower, "tests.cs"), strings.HasSuffix(lower, ".t"):
		return ClassTest
	case strings.Contains(base, ".test."), strings.Contains(base, ".spec."):
		return ClassTest
	}

	if IsRoutePath(p) {
		return ClassRoutes
	}

	for _, d := range docDirs {
		if strings.HasPrefix(lower, d) || strings.Contains(slashed, "/"+d) {
			return ClassDoc
		}
	}
	switch ext {
	case ".md", ".rst", ".txt", ".adoc":
		return ClassDoc
	case ".yml", ".yaml", ".toml", ".ini", ".env", ".properties", ".conf":
		return ClassConfig
	case ".json":
		return ClassConfig
	}
	return ClassSource
}

// specNames are file names that are specifications wherever they appear.
var specNames = []string{"openapi", "swagger", "api-docs", "apispec", "api_spec"}

// IsSpecPath reports whether a path looks like an API description.
func IsSpecPath(p string) bool {
	lower := strings.ToLower(p)
	base := path.Base(lower)
	ext := path.Ext(base)
	switch ext {
	case ".yaml", ".yml", ".json":
	default:
		// A .proto or GraphQL schema is also an interface description.
		return ext == ".proto" || ext == ".graphql" || ext == ".graphqls"
	}
	stem := strings.TrimSuffix(base, ext)
	for _, n := range specNames {
		if strings.Contains(stem, n) {
			return true
		}
	}
	// A YAML or JSON file inside a spec directory is very likely one.
	dir := "/" + strings.TrimSuffix(lower, base)
	for _, d := range []string{"/openapi/", "/spec/openapi/", "/specs/", "/api/spec/", "/docs/api/"} {
		if strings.Contains(dir, d) {
			return true
		}
	}
	return false
}

// routeHints are path fragments that suggest a file declares server routes.
var routeHints = []string{
	"routes", "route", "router", "urls", "controller", "handler", "endpoints",
	"web.php", "api.php",
}

// IsRoutePath reports whether a path is likely to declare server routes.
func IsRoutePath(p string) bool {
	lower := strings.ToLower(p)
	base := path.Base(lower)
	for _, h := range routeHints {
		if strings.Contains(base, h) {
			return true
		}
	}
	switch {
	case strings.HasSuffix(lower, "config/routes.rb"),
		strings.HasSuffix(lower, "urls.py"),
		strings.Contains(lower, "/app/api/"),
		strings.Contains(lower, "/pages/api/"):
		return true
	}
	return false
}
