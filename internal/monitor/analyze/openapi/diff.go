package openapi

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Change is one structural difference between two specifications.
type Change struct {
	// Kind is a stable signal name, e.g. "openapi.required_param_added".
	Kind string
	// Op is the affected operation. A zero Op means the change is
	// document-wide, such as a server or global security change.
	Op OpKey
	// Pointer locates the change in the document, for evidence.
	Pointer string
	Before  string
	After   string
	// Breaking is this package's own judgement, which the caller may downgrade
	// but never upgrades.
	Breaking bool
	Detail   string
}

// Signal names. These appear in findings and in golden files, so they are part
// of the contract.
const (
	SignalPathRemoved        = "openapi.path_removed"
	SignalOperationRemoved   = "openapi.operation_removed"
	SignalRequiredParamAdded = "openapi.required_param_added"
	SignalParamNowRequired   = "openapi.param_now_required"
	SignalParamRemoved       = "openapi.param_removed"
	SignalBodyNowRequired    = "openapi.request_body_required"
	SignalBodyPropRequired   = "openapi.request_body_prop_required"
	SignalTypeNarrowed       = "openapi.type_narrowed"
	SignalEnumValueRemoved   = "openapi.enum_value_removed"
	SignalResponseFieldGone  = "openapi.response_field_removed"
	SignalStatusRemoved      = "openapi.success_status_removed"
	SignalAuthChanged        = "openapi.auth_changed"
	SignalScopeAdded         = "openapi.scope_added"
	SignalDeprecated         = "openapi.deprecated"
	SignalSunset             = "openapi.sunset_announced"
	SignalServerChanged      = "openapi.server_changed"
	SignalAdditive           = "openapi.additive"
	SignalMajorVersionBump   = "openapi.version_major_bump"
	SignalParamRenamed       = "openapi.path_param_renamed"
)

// Diff compares two specifications and returns every structural change.
//
// It reports changes to all operations; selecting the ones that matter to a
// particular caller is the monitor's job, because only the monitor knows which
// endpoints are actually used.
func Diff(base, head *Doc) []Change {
	var out []Change
	if base == nil || head == nil {
		return nil
	}

	// Document-wide changes first.
	if !equalStrings(base.Servers, head.Servers) && len(base.Servers) > 0 {
		out = append(out, Change{
			Kind: SignalServerChanged, Pointer: "#/servers",
			Before: strings.Join(base.Servers, ", "), After: strings.Join(head.Servers, ", "),
			Breaking: true,
			Detail:   "the server URL changed, so existing base URLs may no longer resolve",
		})
	}
	if !equalStrings(base.Security, head.Security) {
		out = append(out, Change{
			Kind: SignalAuthChanged, Pointer: "#/security",
			Before: strings.Join(base.Security, ", "), After: strings.Join(head.Security, ", "),
			Breaking: tightened(base.Security, head.Security),
			Detail:   "the document-wide security requirement changed",
		})
	}
	if majorBump(base.InfoVersion, head.InfoVersion) {
		out = append(out, Change{
			Kind: SignalMajorVersionBump, Pointer: "#/info/version",
			Before: base.InfoVersion, After: head.InfoVersion,
			Detail: "the specification's major version increased",
		})
	}

	// Paths that disappeared entirely.
	//
	// Comparison is on the normalized template, not the literal path. Renaming a
	// path parameter -- /keys/{keyNumberOrProductKey} becoming
	// /keys/{keyNumberOrActivationCode} -- changes the string but not the
	// endpoint, and reporting that as a removal is a false alarm on every
	// caller of the path. Upstreams rename parameters routinely.
	headTemplates := templateIndex(head.Paths)
	for _, p := range sortedKeys(base.Paths) {
		if head.Paths[p] {
			continue
		}
		tmpl := normalizeTemplate(p)
		if renamed, ok := headTemplates[tmpl]; ok {
			out = append(out, Change{
				Kind: SignalParamRenamed, Op: OpKey{Path: p},
				Pointer: pathPointer(p), Before: p, After: renamed,
				Detail: "a path parameter was renamed; the endpoint is unchanged",
			})
			continue
		}
		out = append(out, Change{
			Kind: SignalPathRemoved, Op: OpKey{Path: p},
			Pointer: pathPointer(p), Before: p, Breaking: true,
			Detail: "the path no longer exists in the specification",
		})
	}

	baseKeys := sortedOps(base.Operations)
	for _, key := range baseKeys {
		b := base.Operations[key]
		h, ok := head.Operations[key]
		if !ok {
			// Follow a parameter rename to the operation that replaced it, so a
			// rename is not reported again as an operation removal.
			if renamed, isRename := headTemplates[normalizeTemplate(key.Path)]; isRename && !head.Paths[key.Path] {
				if h2, ok2 := head.Operations[OpKey{Method: key.Method, Path: renamed}]; ok2 {
					out = append(out, diffOperationOpts(b, h2, true)...)
					continue
				}
			}
			// A path-level removal already covers this case; only report the
			// operation when the path itself survives, or the same break would
			// be reported twice.
			if head.Paths[key.Path] {
				out = append(out, Change{
					Kind: SignalOperationRemoved, Op: key, Pointer: opPointer(key),
					Before: key.String(), Breaking: true,
					Detail: "the operation was removed from the specification",
				})
			}
			continue
		}
		out = append(out, diffOperation(b, h)...)
	}

	// Newly added operations are informational: they cannot break a caller.
	for _, key := range sortedOps(head.Operations) {
		if _, ok := base.Operations[key]; !ok {
			out = append(out, Change{
				Kind: SignalAdditive, Op: key, Pointer: opPointer(key),
				After: key.String(), Detail: "a new operation was added",
			})
		}
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Op.Path != out[j].Op.Path {
			return out[i].Op.Path < out[j].Op.Path
		}
		if out[i].Op.Method != out[j].Op.Method {
			return out[i].Op.Method < out[j].Op.Method
		}
		return out[i].Kind < out[j].Kind
	})
	return out
}

func diffOperation(b, h *Operation) []Change {
	return diffOperationOpts(b, h, false)
}

// diffOperationOpts compares two operations. renamedPath suppresses path
// parameter differences, which is required when the two operations were matched
// through a parameter rename: the name changed but the position in the template
// did not, so reporting a removal plus a new required parameter would describe
// the same rename twice more -- and "new required parameter" is a breaking
// signal, so it would raise a false alarm on an endpoint nothing happened to.
func diffOperationOpts(b, h *Operation, renamedPath bool) []Change {
	var out []Change
	key := b.Key

	// Parameters.
	for name, bp := range b.Params {
		if renamedPath && strings.EqualFold(bp.In, "path") {
			continue
		}
		hp, ok := h.Params[name]
		if !ok {
			// Removing a parameter a caller sends is usually tolerated by
			// servers, so this is a risk rather than a certain break.
			out = append(out, Change{
				Kind: SignalParamRemoved, Op: key,
				Pointer: opPointer(key) + "/parameters/" + name,
				Before:  name, Detail: "a parameter was removed",
			})
			continue
		}
		if !bp.Required && hp.Required {
			out = append(out, Change{
				Kind: SignalParamNowRequired, Op: key,
				Pointer: opPointer(key) + "/parameters/" + name,
				Before:  "optional", After: "required", Breaking: true,
				Detail: fmt.Sprintf("parameter %q became required", hp.Name),
			})
		}
		if bp.Type != "" && hp.Type != "" && bp.Type != hp.Type {
			out = append(out, Change{
				Kind: SignalTypeNarrowed, Op: key,
				Pointer: opPointer(key) + "/parameters/" + name,
				Before:  bp.Type, After: hp.Type, Breaking: true,
				Detail: fmt.Sprintf("parameter %q changed type", hp.Name),
			})
		}
		if removed := missing(bp.Enum, hp.Enum); len(removed) > 0 {
			out = append(out, Change{
				Kind: SignalEnumValueRemoved, Op: key,
				Pointer: opPointer(key) + "/parameters/" + name,
				Before:  strings.Join(removed, ", "), Breaking: true,
				Detail: fmt.Sprintf("parameter %q no longer accepts %s", hp.Name, strings.Join(removed, ", ")),
			})
		}
	}
	for name, hp := range h.Params {
		if _, ok := b.Params[name]; ok {
			continue
		}
		if renamedPath && strings.EqualFold(hp.In, "path") {
			continue
		}
		if hp.Required {
			out = append(out, Change{
				Kind: SignalRequiredParamAdded, Op: key,
				Pointer: opPointer(key) + "/parameters/" + name,
				After:   name, Breaking: true,
				Detail: fmt.Sprintf("a new required %s parameter %q was added", hp.In, hp.Name),
			})
			continue
		}
		out = append(out, Change{
			Kind: SignalAdditive, Op: key,
			Pointer: opPointer(key) + "/parameters/" + name,
			After:   name, Detail: fmt.Sprintf("a new optional parameter %q was added", hp.Name),
		})
	}

	// Request body.
	if !b.BodyRequired && h.BodyRequired {
		out = append(out, Change{
			Kind: SignalBodyNowRequired, Op: key, Pointer: opPointer(key) + "/requestBody",
			Before: "optional", After: "required", Breaking: true,
			Detail: "the request body became required",
		})
	}
	for name := range h.BodyRequiredProps {
		if !b.BodyRequiredProps[name] {
			out = append(out, Change{
				Kind: SignalBodyPropRequired, Op: key,
				Pointer: opPointer(key) + "/requestBody/required/" + name,
				After:   name, Breaking: true,
				Detail: fmt.Sprintf("request body property %q became required", name),
			})
		}
	}

	// Responses. A removed field is a risk in general, but breaking when the
	// caller was promised it.
	for code, bfields := range b.ResponseFields {
		if !isSuccess(code) {
			continue
		}
		hfields, ok := h.ResponseFields[code]
		if !ok {
			continue
		}
		var names []string
		for name := range bfields {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			if _, still := hfields[name]; still {
				continue
			}
			out = append(out, Change{
				Kind: SignalResponseFieldGone, Op: key,
				Pointer:  opPointer(key) + "/responses/" + code + "/" + name,
				Before:   name,
				Breaking: bfields[name],
				Detail:   fmt.Sprintf("response field %q was removed from the %s response", name, code),
			})
		}
	}
	if removed := missingSuccess(b.Statuses, h.Statuses); len(removed) > 0 {
		out = append(out, Change{
			Kind: SignalStatusRemoved, Op: key, Pointer: opPointer(key) + "/responses",
			Before: strings.Join(removed, ", "),
			Detail: "a documented success status was removed",
		})
	}

	// Security.
	if !equalStrings(b.Security, h.Security) && (b.HasSecurity || h.HasSecurity) {
		breaking := tightened(b.Security, h.Security)
		kind := SignalAuthChanged
		if !breaking && len(h.Security) == len(b.Security) {
			kind = SignalScopeAdded
		}
		out = append(out, Change{
			Kind: kind, Op: key, Pointer: opPointer(key) + "/security",
			Before: strings.Join(b.Security, ", "), After: strings.Join(h.Security, ", "),
			Breaking: breaking,
			Detail:   "the authentication requirement changed",
		})
	}

	// Deprecation and sunset are warnings, never breaks: the endpoint still
	// works today, which is exactly why they are worth surfacing early.
	if !b.Deprecated && h.Deprecated {
		out = append(out, Change{
			Kind: SignalDeprecated, Op: key, Pointer: opPointer(key) + "/deprecated",
			After: "true", Detail: "the operation was marked deprecated",
		})
	}
	if b.Sunset == "" && h.Sunset != "" {
		out = append(out, Change{
			Kind: SignalSunset, Op: key, Pointer: opPointer(key) + "/x-sunset",
			After: h.Sunset, Detail: "a sunset date was announced: " + h.Sunset,
		})
	}
	return out
}

// tightened reports whether the security requirement became stricter, which is
// the case that breaks a caller. Loosening it cannot.
func tightened(before, after []string) bool {
	if len(before) == 0 && len(after) > 0 {
		return true
	}
	return len(missing(before, after)) == 0 && len(after) > len(before)
}

// missing returns entries of before that are absent from after.
func missing(before, after []string) []string {
	have := make(map[string]bool, len(after))
	for _, s := range after {
		have[s] = true
	}
	var out []string
	for _, s := range before {
		if !have[s] {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func missingSuccess(before, after []string) []string {
	var b, a []string
	for _, s := range before {
		if isSuccess(s) {
			b = append(b, s)
		}
	}
	for _, s := range after {
		if isSuccess(s) {
			a = append(a, s)
		}
	}
	if len(a) == 0 {
		// Nothing documented afterwards is a documentation gap, not a break.
		return nil
	}
	return missing(b, a)
}

func isSuccess(code string) bool {
	if code == "default" {
		return false
	}
	n, err := strconv.Atoi(strings.TrimSpace(code))
	if err != nil {
		return strings.HasPrefix(code, "2")
	}
	return n >= 200 && n < 300
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// majorBump reports whether the major component of a semantic version grew.
func majorBump(before, after string) bool {
	bm, ok1 := majorOf(before)
	am, ok2 := majorOf(after)
	return ok1 && ok2 && am > bm
}

func majorOf(v string) (int, bool) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if v == "" {
		return 0, false
	}
	part := v
	if i := strings.IndexAny(v, ".-+"); i >= 0 {
		part = v[:i]
	}
	n, err := strconv.Atoi(part)
	if err != nil {
		return 0, false
	}
	return n, true
}

// escapePointer encodes a JSON Pointer token per RFC 6901.
func escapePointer(s string) string {
	s = strings.ReplaceAll(s, "~", "~0")
	return strings.ReplaceAll(s, "/", "~1")
}

func pathPointer(p string) string { return "#/paths/" + escapePointer(p) }

// paramRe matches an OpenAPI path parameter.
var paramRe = regexp.MustCompile(`\{[^/}]*\}`)

// normalizeTemplate collapses every path parameter to a bare "{}" so two
// spellings of the same endpoint compare equal.
func normalizeTemplate(p string) string { return paramRe.ReplaceAllString(p, "{}") }

// templateIndex maps each normalized template to a path that has it. Only
// parameterised paths can be renamed, so literal paths are skipped: they would
// map to themselves and mask a real removal.
func templateIndex(paths map[string]bool) map[string]string {
	out := make(map[string]string, len(paths))
	for _, p := range sortedKeys(paths) {
		t := normalizeTemplate(p)
		if t == p {
			continue
		}
		if _, exists := out[t]; !exists {
			out[t] = p
		}
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func opPointer(k OpKey) string {
	return pathPointer(k.Path) + "/" + strings.ToLower(k.Method)
}

func sortedOps(m map[OpKey]*Operation) []OpKey {
	out := make([]OpKey, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Method < out[j].Method
	})
	return out
}
