// Package ghsource fetches the upstream history the monitor reasons about.
//
// It exists as an interface with one real implementation and one fake so the
// monitor can be tested exhaustively without a network, and so a different
// backend could be substituted later without touching analysis code.
//
// Two constraints shape the design. First, the GitHub API is rate limited, so
// every request is conditional where possible: a 304 response costs nothing
// against the quota, which makes "check often, change rarely" cheap. Second, a
// tool that exhausts a developer's rate limit to report nothing is worse than
// one that stops early, so the caller is always told what the budget looks like
// and can stop rather than spend it all.
package ghsource

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// RepoID identifies a repository.
type RepoID struct {
	Owner string
	Name  string
}

// String renders "owner/name".
func (r RepoID) String() string { return r.Owner + "/" + r.Name }

// Repo is the subset of repository metadata the monitor uses.
type Repo struct {
	FullName      string
	HTMLURL       string
	DefaultBranch string
	PushedAt      time.Time
	Archived      bool
	Disabled      bool
	Private       bool
}

// Commit is one upstream commit.
type Commit struct {
	SHA        string
	Message    string
	HTMLURL    string
	Author     string
	AuthorDate time.Time
}

// FileChange is one file in a comparison.
type FileChange struct {
	Filename         string
	PreviousFilename string
	Status           string
	Additions        int
	Deletions        int
	Changes          int
	// Patch is the unified diff. GitHub omits it for binary and very large
	// files, which is why the spec analyzer fetches whole documents instead of
	// relying on it.
	Patch        string
	PatchOmitted bool
	SHA          string
	BlobURL      string
	RawURL       string
}

// Compare is the result of comparing two refs.
type Compare struct {
	Status       string
	AheadBy      int
	BehindBy     int
	TotalCommits int
	BaseSHA      string
	HeadSHA      string
	HTMLURL      string
	Commits      []Commit
	Files        []FileChange
	// FilesTruncated means the file list was cut short, so absence of a file
	// proves nothing. Analysis must degrade rather than conclude.
	FilesTruncated bool
}

// Release is a published release.
type Release struct {
	TagName     string
	Name        string
	Body        string
	HTMLURL     string
	Draft       bool
	Prerelease  bool
	PublishedAt time.Time
}

// Tag is a git tag.
type Tag struct {
	Name string
	SHA  string
}

// FileContent is a file at a specific ref.
type FileContent struct {
	Path      string
	SHA       string
	Content   []byte
	Truncated bool
}

// Cond carries validators for a conditional request.
type Cond struct {
	ETag         string
	LastModified string
}

// Rate is the state of one rate-limit bucket.
type Rate struct {
	Resource  string
	Limit     int
	Remaining int
	Used      int
	Reset     time.Time
}

// Meta describes how a request went, independently of its payload.
type Meta struct {
	ETag         string
	LastModified string
	// NotModified means the server returned 304 and the payload is unchanged.
	NotModified bool
	Rate        Rate
	// Calls counts the HTTP requests actually issued, including pagination, so
	// the caller can account for its budget honestly.
	Calls int
}

// ListOptions bounds a paginated read. Every list call has a page cap: an
// unbounded fetch against a busy repository is how a tool accidentally spends
// an entire hour's quota.
type ListOptions struct {
	PerPage  int
	MaxPages int
}

// CompareOptions bounds a comparison.
type CompareOptions struct {
	Cond     Cond
	MaxFiles int
	// PathPrefix restricts results to a monorepo subdirectory.
	PathPrefix string
}

// GitHubSource is the seam between the monitor and the outside world.
type GitHubSource interface {
	// Repo fetches repository metadata. Cheap, conditional, and the gate that
	// lets an unchanged repository be skipped entirely.
	Repo(ctx context.Context, r RepoID, c Cond) (*Repo, Meta, error)
	// Compare returns the commits and file diffs between two refs.
	Compare(ctx context.Context, r RepoID, base, head string, o CompareOptions) (*Compare, Meta, error)
	// CommitsSince lists commits after a time, used to recover when a stored
	// base SHA has been garbage collected by a force push.
	CommitsSince(ctx context.Context, r RepoID, since time.Time, path string, o ListOptions) ([]Commit, Meta, error)
	Releases(ctx context.Context, r RepoID, c Cond, o ListOptions) ([]Release, Meta, error)
	Tags(ctx context.Context, r RepoID, c Cond, o ListOptions) ([]Tag, Meta, error)
	// FileAtRef fetches a whole file at a ref. The spec analyzer needs both
	// sides of a change in full, because a unified diff of a large
	// specification is usually omitted and useless even when present.
	FileAtRef(ctx context.Context, r RepoID, path, ref string, c Cond) (*FileContent, Meta, error)
	// ListTree lists paths under a prefix, used once per repository to discover
	// where its specification lives.
	ListTree(ctx context.Context, r RepoID, ref, pathPrefix string) ([]string, Meta, error)
	RateLimits(ctx context.Context) (map[string]Rate, error)
}

// Typed errors. The orchestrator reacts to these rather than matching on
// message text, so behaviour cannot drift when a message is reworded.
var (
	// ErrUnauthenticated means no usable credential was found.
	ErrUnauthenticated = errors.New("no GitHub token available")
)

// NotFoundError means the repository, ref or path does not exist, or the token
// cannot see it. GitHub deliberately conflates "absent" and "forbidden" for
// private resources, so these cannot be distinguished.
type NotFoundError struct {
	Repo RepoID
	Path string
}

func (e *NotFoundError) Error() string {
	if e.Path != "" {
		return fmt.Sprintf("%s: %s not found (or not visible to this token)", e.Repo, e.Path)
	}
	return fmt.Sprintf("%s not found (or not visible to this token)", e.Repo)
}

// ForbiddenError means the request was rejected for reasons other than rate
// limiting.
type ForbiddenError struct {
	Repo   RepoID
	Detail string
}

func (e *ForbiddenError) Error() string {
	return fmt.Sprintf("%s: access forbidden: %s", e.Repo, e.Detail)
}

// RateLimitedError means the quota is spent or a secondary limit was tripped.
type RateLimitedError struct {
	RetryAfter time.Duration
	Reset      time.Time
	// Secondary marks GitHub's abuse-detection limit, which is time-based
	// rather than quota-based and must be honoured by waiting, not retried.
	Secondary bool
}

func (e *RateLimitedError) Error() string {
	if e.Secondary {
		return fmt.Sprintf("GitHub secondary rate limit; retry after %s", e.RetryAfter)
	}
	return fmt.Sprintf("GitHub rate limit exhausted; resets at %s", e.Reset.Format(time.RFC3339))
}

// TooLargeError means the resource exceeded a configured size cap.
type TooLargeError struct {
	Path  string
	Bytes int64
}

func (e *TooLargeError) Error() string {
	return fmt.Sprintf("%s is %d bytes, larger than the configured limit", e.Path, e.Bytes)
}

// BadRefError means a ref could not be resolved.
type BadRefError struct {
	Repo RepoID
	Ref  string
}

func (e *BadRefError) Error() string {
	return fmt.Sprintf("%s: cannot resolve ref %q", e.Repo, e.Ref)
}

// IsNotFound reports whether err is a NotFoundError.
func IsNotFound(err error) bool {
	var e *NotFoundError
	return errors.As(err, &e)
}

// IsRateLimited reports whether err is a RateLimitedError.
func IsRateLimited(err error) bool {
	var e *RateLimitedError
	return errors.As(err, &e)
}

// IsBadRef reports whether err is a BadRefError.
func IsBadRef(err error) bool {
	var e *BadRefError
	return errors.As(err, &e)
}
