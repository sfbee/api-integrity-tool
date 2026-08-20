package index

import (
	"sort"
)

// MergeOptions tunes how a fresh scan is folded into the previous index.
type MergeOptions struct {
	// PruneAfterMissingScans drops a call that has been absent for this many
	// consecutive scans. Zero means never prune. Keeping removed calls around
	// briefly is what lets the tool say "this endpoint disappeared" instead of
	// silently forgetting it.
	PruneAfterMissingScans int
	// Partial marks a scan that could not have seen the whole repo, because
	// language or path filters narrowed traversal.
	Partial bool
	// PartialScope reports whether a previously-known call was in scope for this
	// scan. It is only consulted when Partial is set, and it is the guard that
	// stops a filtered scan from marking the rest of the index removed -- the
	// bug that would quietly destroy a team's curated index.
	PartialScope func(Call) bool
}

// DefaultPruneAfterMissingScans is the built-in retention for removed calls.
const DefaultPruneAfterMissingScans = 5

// Relocation records a call that moved.
type Relocation struct {
	ID      string `json:"id"`
	OldFile string `json:"old_file"`
	NewFile string `json:"new_file"`
	OldLine int    `json:"old_line"`
	NewLine int    `json:"new_line"`
}

// MergeReport summarizes what changed, and is what CI prints when it wants to
// comment "this PR adds 2 outbound calls to a new host".
type MergeReport struct {
	Added      int          `json:"added"`
	Updated    int          `json:"updated"`
	Unchanged  int          `json:"unchanged"`
	Removed    int          `json:"removed"`
	Restored   int          `json:"restored"`
	Pruned     int          `json:"pruned"`
	CarriedFwd int          `json:"carried_forward"`
	AddedIDs   []string     `json:"added_ids,omitempty"`
	RemovedIDs []string     `json:"removed_ids,omitempty"`
	Relocated  []Relocation `json:"relocated,omitempty"`
}

// Changed reports whether the merge altered the set of calls, which is what
// `scan --check` uses as a CI drift gate.
func (r *MergeReport) Changed() bool {
	return r.Added > 0 || r.Removed > 0 || r.Restored > 0 || r.Pruned > 0 || len(r.Relocated) > 0
}

// Merge folds next into prev, preserving lifecycle history, and returns the
// merged index. next is treated as the authority for everything it observed;
// prev is the authority for everything out of scope.
//
// prev may be nil, which is the first-scan case.
func Merge(prev, next *Index, opts MergeOptions) (*Index, *MergeReport) {
	rep := &MergeReport{}
	out := *next
	scanID, commit := next.Scan.ID, next.Scan.Commit

	if prev == nil {
		calls := make([]Call, len(next.Calls))
		copy(calls, next.Calls)
		for i := range calls {
			calls[i].Lifecycle = Lifecycle{
				FirstSeenScan: scanID, FirstSeenCommit: commit,
				LastSeenScan: scanID, LastSeenCommit: commit,
				Status: StatusActive,
			}
			rep.AddedIDs = append(rep.AddedIDs, calls[i].ID)
		}
		rep.Added = len(calls)
		out.Calls = calls
		finish(&out)
		sort.Strings(rep.AddedIDs)
		return &out, rep
	}

	// Three lookup tiers, tried narrowest first: exact ID, then same file with
	// the same target (the line moved), then same target anywhere (the file was
	// renamed).
	byID := make(map[string]*Call, len(prev.Calls))
	byFileFP := make(map[string][]*Call, len(prev.Calls))
	byFP := make(map[string][]*Call, len(prev.Calls))
	for i := range prev.Calls {
		c := &prev.Calls[i]
		byID[c.ID] = c
		byFileFP[c.Location.File+"\x00"+c.Fingerprint] = append(byFileFP[c.Location.File+"\x00"+c.Fingerprint], c)
		byFP[c.Fingerprint] = append(byFP[c.Fingerprint], c)
	}

	matched := map[string]bool{}
	calls := make([]Call, 0, len(next.Calls)+len(prev.Calls))

	for _, c := range next.Calls {
		cur := c
		old, how := findPrev(&cur, byID, byFileFP, byFP, matched)
		switch {
		case old == nil:
			cur.Lifecycle = Lifecycle{
				FirstSeenScan: scanID, FirstSeenCommit: commit,
				LastSeenScan: scanID, LastSeenCommit: commit,
				Status: StatusActive,
			}
			rep.Added++
			rep.AddedIDs = append(rep.AddedIDs, cur.ID)
		default:
			matched[old.ID] = true
			cur.Lifecycle = Lifecycle{
				FirstSeenScan:   firstNonEmpty(old.Lifecycle.FirstSeenScan, scanID),
				FirstSeenCommit: firstNonEmpty(old.Lifecycle.FirstSeenCommit, commit),
				LastSeenScan:    scanID,
				LastSeenCommit:  commit,
				Status:          StatusActive,
			}
			if old.Lifecycle.Status == StatusRemoved {
				rep.Restored++
			} else if how != matchExact || old.Location.Line != cur.Location.Line {
				rep.Updated++
			} else {
				rep.Unchanged++
			}
			if old.Location.File != cur.Location.File || old.Location.Line != cur.Location.Line {
				rep.Relocated = append(rep.Relocated, Relocation{
					ID: cur.ID, OldFile: old.Location.File, NewFile: cur.Location.File,
					OldLine: old.Location.Line, NewLine: cur.Location.Line,
				})
			}
		}
		calls = append(calls, cur)
	}

	prune := opts.PruneAfterMissingScans
	for i := range prev.Calls {
		old := prev.Calls[i]
		if matched[old.ID] {
			continue
		}
		// A narrowed scan cannot testify about calls it never looked at.
		if opts.Partial && opts.PartialScope != nil && !opts.PartialScope(old) {
			rep.CarriedFwd++
			calls = append(calls, old)
			continue
		}
		old.Lifecycle.MissingScans++
		old.Lifecycle.Status = StatusRemoved
		old.Lifecycle.LastSeenScan = firstNonEmpty(old.Lifecycle.LastSeenScan, scanID)
		if prune > 0 && old.Lifecycle.MissingScans > prune {
			rep.Pruned++
			continue
		}
		rep.Removed++
		rep.RemovedIDs = append(rep.RemovedIDs, old.ID)
		calls = append(calls, old)
	}

	out.Calls = calls
	finish(&out)
	sort.Strings(rep.AddedIDs)
	sort.Strings(rep.RemovedIDs)
	sort.Slice(rep.Relocated, func(i, j int) bool { return rep.Relocated[i].ID < rep.Relocated[j].ID })
	return &out, rep
}

type matchKind int

const (
	matchNone matchKind = iota
	matchExact
	matchSameFile
	matchRenamedFile
)

// findPrev locates the previous record for c, narrowest match first. The
// fingerprint-only tier requires a unique unmatched candidate: guessing among
// several would attribute history to the wrong call site.
func findPrev(c *Call, byID map[string]*Call, byFileFP, byFP map[string][]*Call, matched map[string]bool) (*Call, matchKind) {
	if old, ok := byID[c.ID]; ok && !matched[old.ID] {
		return old, matchExact
	}
	if cands := unmatched(byFileFP[c.Location.File+"\x00"+c.Fingerprint], matched); len(cands) == 1 {
		return cands[0], matchSameFile
	}
	if cands := unmatched(byFP[c.Fingerprint], matched); len(cands) == 1 {
		return cands[0], matchRenamedFile
	}
	return nil, matchNone
}

func unmatched(in []*Call, matched map[string]bool) []*Call {
	out := make([]*Call, 0, len(in))
	for _, c := range in {
		if !matched[c.ID] {
			out = append(out, c)
		}
	}
	return out
}

// finish recomputes everything derived. Derived data is never merged, so it
// cannot drift out of step with the calls it summarizes.
func finish(i *Index) {
	i.SchemaVersion = SchemaVersion
	Sort(i.Calls)
	vendors := map[string]string{}
	for _, c := range i.Calls {
		if c.Vendor != "" {
			vendors[c.Host] = c.Vendor
		}
	}
	i.Hosts = BuildHosts(i.Calls, vendors)
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
