package openapi

import (
	"strings"
	"testing"
)

const baseSpec = `
openapi: 3.0.3
info:
  title: Billing
  version: 1.4.0
servers:
  - url: https://api.acme.com/v1
security:
  - apiKey: []
paths:
  /users:
    get:
      parameters:
        - name: limit
          in: query
          required: false
          schema: {type: integer}
      responses:
        "200":
          content:
            application/json:
              schema:
                type: object
                required: [id, email]
                properties:
                  id: {type: string}
                  email: {type: string}
                  nickname: {type: string}
    post:
      requestBody:
        required: false
        content:
          application/json:
            schema:
              type: object
              required: [email]
              properties:
                email: {type: string}
                name: {type: string}
      responses:
        "201": {description: created}
  /users/{id}:
    get:
      parameters:
        - name: id
          in: path
          schema: {type: string}
      responses:
        "200": {description: ok}
  /legacy:
    get:
      responses:
        "200": {description: ok}
`

func parse(t *testing.T, s string) *Doc {
	t.Helper()
	d, err := Parse([]byte(s))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return d
}

// find returns the first change of a kind for an operation path.
func find(changes []Change, kind, path string) (Change, bool) {
	for _, c := range changes {
		if c.Kind == kind && (path == "" || c.Op.Path == path) {
			return c, true
		}
	}
	return Change{}, false
}

func TestParseReadsOperations(t *testing.T) {
	t.Parallel()
	d := parse(t, baseSpec)
	if d.SpecVersion != "3.0.3" || d.InfoVersion != "1.4.0" {
		t.Errorf("versions = %q / %q", d.SpecVersion, d.InfoVersion)
	}
	if len(d.Operations) != 4 {
		t.Errorf("operations = %d, want 4", len(d.Operations))
	}
	op := d.Operations[OpKey{Method: "GET", Path: "/users"}]
	if op == nil {
		t.Fatal("GET /users missing")
	}
	// A required field in the response schema must be recorded as required, so
	// its later removal can be classified as breaking rather than merely risky.
	if req, ok := op.ResponseFields["200"]["email"]; !ok || !req {
		t.Errorf("email required = %v, %v; want recorded as required", req, ok)
	}
	if req := op.ResponseFields["200"]["nickname"]; req {
		t.Error("nickname should be optional")
	}
	// A path parameter is required by definition even when the file omits it.
	idOp := d.Operations[OpKey{Method: "GET", Path: "/users/{id}"}]
	if p, ok := idOp.Params["path:id"]; !ok || !p.Required {
		t.Errorf("path parameter should be required regardless of the file: %+v", p)
	}
}

func TestPathAndOperationRemoval(t *testing.T) {
	t.Parallel()
	head := strings.Replace(baseSpec, `  /legacy:
    get:
      responses:
        "200": {description: ok}
`, "", 1)
	changes := Diff(parse(t, baseSpec), parse(t, head))
	c, ok := find(changes, SignalPathRemoved, "/legacy")
	if !ok {
		t.Fatalf("want a path_removed change, got %+v", kinds(changes))
	}
	if !c.Breaking {
		t.Error("removing a path must be breaking")
	}
	// The same break must not also be reported as an operation removal.
	if _, dup := find(changes, SignalOperationRemoved, "/legacy"); dup {
		t.Error("a removed path should not also report its operations as removed")
	}
}

func TestOperationRemovedWhenPathSurvives(t *testing.T) {
	t.Parallel()
	head := strings.Replace(baseSpec, `    post:
      requestBody:`, `    x-removed:
      requestBody:`, 1)
	changes := Diff(parse(t, baseSpec), parse(t, head))
	c, ok := find(changes, SignalOperationRemoved, "/users")
	if !ok {
		t.Fatalf("want operation_removed, got %+v", kinds(changes))
	}
	if !c.Breaking || c.Op.Method != "POST" {
		t.Errorf("change = %+v", c)
	}
}

func TestRequiredParameterAddedIsBreaking(t *testing.T) {
	t.Parallel()
	head := strings.Replace(baseSpec, `        - name: limit
          in: query
          required: false`, `        - name: tenant
          in: query
          required: true
        - name: limit
          in: query
          required: false`, 1)
	changes := Diff(parse(t, baseSpec), parse(t, head))
	c, ok := find(changes, SignalRequiredParamAdded, "/users")
	if !ok {
		t.Fatalf("want required_param_added, got %+v", kinds(changes))
	}
	if !c.Breaking {
		t.Error("a new required parameter must be breaking")
	}
}

// A new optional parameter cannot break anyone and must stay informational,
// or every routine addition becomes noise.
func TestOptionalParameterAddedIsAdditive(t *testing.T) {
	t.Parallel()
	head := strings.Replace(baseSpec, `        - name: limit
          in: query
          required: false`, `        - name: cursor
          in: query
          required: false
        - name: limit
          in: query
          required: false`, 1)
	changes := Diff(parse(t, baseSpec), parse(t, head))
	c, ok := find(changes, SignalAdditive, "/users")
	if !ok {
		t.Fatalf("want an additive change, got %+v", kinds(changes))
	}
	if c.Breaking {
		t.Error("an optional addition must never be breaking")
	}
}

func TestParameterBecomingRequiredIsBreaking(t *testing.T) {
	t.Parallel()
	head := strings.Replace(baseSpec, `        - name: limit
          in: query
          required: false`, `        - name: limit
          in: query
          required: true`, 1)
	changes := Diff(parse(t, baseSpec), parse(t, head))
	c, ok := find(changes, SignalParamNowRequired, "/users")
	if !ok || !c.Breaking {
		t.Fatalf("want a breaking param_now_required, got %+v", kinds(changes))
	}
}

// The distinction that makes response diffs trustworthy: losing a field the
// specification promised is a break; losing an optional one is a risk.
func TestResponseFieldRemovalSeverityDependsOnRequired(t *testing.T) {
	t.Parallel()
	t.Run("required field", func(t *testing.T) {
		t.Parallel()
		head := strings.Replace(baseSpec, "                  email: {type: string}\n", "", 1)
		changes := Diff(parse(t, baseSpec), parse(t, head))
		c, ok := find(changes, SignalResponseFieldGone, "/users")
		if !ok {
			t.Fatalf("want response_field_removed, got %+v", kinds(changes))
		}
		if !c.Breaking {
			t.Error("removing a required response field must be breaking")
		}
	})
	t.Run("optional field", func(t *testing.T) {
		t.Parallel()
		head := strings.Replace(baseSpec, "                  nickname: {type: string}\n", "", 1)
		changes := Diff(parse(t, baseSpec), parse(t, head))
		c, ok := find(changes, SignalResponseFieldGone, "/users")
		if !ok {
			t.Fatalf("want response_field_removed, got %+v", kinds(changes))
		}
		if c.Breaking {
			t.Error("removing an optional response field should not be breaking")
		}
	})
}

func TestRequestBodyBecomingRequired(t *testing.T) {
	t.Parallel()
	head := strings.Replace(baseSpec, "      requestBody:\n        required: false", "      requestBody:\n        required: true", 1)
	changes := Diff(parse(t, baseSpec), parse(t, head))
	if c, ok := find(changes, SignalBodyNowRequired, "/users"); !ok || !c.Breaking {
		t.Fatalf("want a breaking request_body_required, got %+v", kinds(changes))
	}
}

func TestNewRequiredBodyPropertyIsBreaking(t *testing.T) {
	t.Parallel()
	head := strings.Replace(baseSpec, "              required: [email]", "              required: [email, name]", 1)
	changes := Diff(parse(t, baseSpec), parse(t, head))
	if c, ok := find(changes, SignalBodyPropRequired, "/users"); !ok || !c.Breaking {
		t.Fatalf("want a breaking request_body_prop_required, got %+v", kinds(changes))
	}
}

func TestAuthTighteningIsBreakingLooseningIsNot(t *testing.T) {
	t.Parallel()
	t.Run("added", func(t *testing.T) {
		t.Parallel()
		head := strings.Replace(baseSpec, "security:\n  - apiKey: []", "security:\n  - apiKey: []\n  - oauth2: [write]", 1)
		changes := Diff(parse(t, baseSpec), parse(t, head))
		if c, ok := find(changes, SignalAuthChanged, ""); !ok || !c.Breaking {
			t.Fatalf("want a breaking auth change, got %+v", kinds(changes))
		}
	})
	t.Run("removed", func(t *testing.T) {
		t.Parallel()
		head := strings.Replace(baseSpec, "security:\n  - apiKey: []", "security: []", 1)
		changes := Diff(parse(t, baseSpec), parse(t, head))
		c, ok := find(changes, SignalAuthChanged, "")
		if !ok {
			t.Fatalf("want an auth change, got %+v", kinds(changes))
		}
		if c.Breaking {
			t.Error("relaxing authentication cannot break a caller")
		}
	})
}

func TestDeprecationAndSunsetAreWarningsNotBreaks(t *testing.T) {
	t.Parallel()
	head := strings.Replace(baseSpec, `  /legacy:
    get:
      responses:`, `  /legacy:
    get:
      deprecated: true
      x-sunset: "2026-12-31"
      responses:`, 1)
	changes := Diff(parse(t, baseSpec), parse(t, head))
	dep, ok := find(changes, SignalDeprecated, "/legacy")
	if !ok {
		t.Fatalf("want a deprecation change, got %+v", kinds(changes))
	}
	if dep.Breaking {
		t.Error("deprecation is a warning: the endpoint still works today")
	}
	if s, ok := find(changes, SignalSunset, "/legacy"); !ok || s.After != "2026-12-31" {
		t.Errorf("sunset change = %+v", s)
	}
}

func TestServerChangeIsBreaking(t *testing.T) {
	t.Parallel()
	head := strings.Replace(baseSpec, "https://api.acme.com/v1", "https://api.acme.com/v2", 1)
	changes := Diff(parse(t, baseSpec), parse(t, head))
	if c, ok := find(changes, SignalServerChanged, ""); !ok || !c.Breaking {
		t.Fatalf("want a breaking server change, got %+v", kinds(changes))
	}
}

func TestMajorVersionBump(t *testing.T) {
	t.Parallel()
	head := strings.Replace(baseSpec, "version: 1.4.0", "version: 2.0.0", 1)
	changes := Diff(parse(t, baseSpec), parse(t, head))
	if _, ok := find(changes, SignalMajorVersionBump, ""); !ok {
		t.Fatalf("want a major version bump, got %+v", kinds(changes))
	}
	// A minor bump must not be reported at all.
	minor := strings.Replace(baseSpec, "version: 1.4.0", "version: 1.5.0", 1)
	if _, ok := find(Diff(parse(t, baseSpec), parse(t, minor)), SignalMajorVersionBump, ""); ok {
		t.Error("a minor version bump should not be reported")
	}
}

// An identical document must produce no changes at all. Without this, every
// check reports noise on every run.
func TestIdenticalSpecsProduceNoChanges(t *testing.T) {
	t.Parallel()
	if got := Diff(parse(t, baseSpec), parse(t, baseSpec)); len(got) != 0 {
		t.Errorf("identical specs produced %d changes: %+v", len(got), kinds(got))
	}
}

func TestRefsAreResolved(t *testing.T) {
	t.Parallel()
	spec := `
openapi: 3.0.0
info: {version: 1.0.0}
paths:
  /widgets:
    get:
      responses:
        "200":
          content:
            application/json:
              schema: {$ref: "#/components/schemas/Widget"}
components:
  schemas:
    Widget:
      type: object
      required: [sku]
      properties:
        sku: {type: string}
        colour: {type: string}
`
	d := parse(t, spec)
	op := d.Operations[OpKey{Method: "GET", Path: "/widgets"}]
	if op == nil {
		t.Fatal("operation missing")
	}
	if req, ok := op.ResponseFields["200"]["sku"]; !ok || !req {
		t.Errorf("a $ref schema was not resolved: %+v", op.ResponseFields)
	}
}

// A remote $ref must not be fetched: that would make analysis non-hermetic and
// turn someone else's specification into an SSRF vector.
func TestRemoteRefsAreNotFetched(t *testing.T) {
	t.Parallel()
	spec := `
openapi: 3.0.0
info: {version: 1.0.0}
paths:
  /x:
    get:
      responses:
        "200":
          content:
            application/json:
              schema: {$ref: "https://evil.example/schema.json"}
`
	d := parse(t, spec)
	op := d.Operations[OpKey{Method: "GET", Path: "/x"}]
	if len(op.ResponseFields["200"]) != 0 {
		t.Errorf("a remote ref was resolved: %+v", op.ResponseFields)
	}
}

func TestSwagger2BasePathAndBodyParameter(t *testing.T) {
	t.Parallel()
	spec := `
swagger: "2.0"
info: {version: 1.0.0}
host: api.acme.com
basePath: /v1
paths:
  /things:
    post:
      parameters:
        - name: body
          in: body
          required: true
          schema: {type: object}
      responses:
        "200": {description: ok}
`
	d := parse(t, spec)
	op := d.Operations[OpKey{Method: "POST", Path: "/v1/things"}]
	if op == nil {
		t.Fatalf("basePath was not applied: %+v", d.Paths)
	}
	if !op.BodyRequired {
		t.Error("a required in:body parameter should mark the body required")
	}
}

func TestMalformedSpecIsAnErrorNotAPanic(t *testing.T) {
	t.Parallel()
	for _, body := range []string{"", "not: a: spec", "[]", "openapi: 3.0.0\npaths: 12"} {
		if _, err := Parse([]byte(body)); err == nil && body != "openapi: 3.0.0\npaths: 12" {
			t.Errorf("Parse(%q) succeeded, want an error", body)
		}
	}
}

func kinds(cs []Change) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.Kind+"@"+c.Op.String())
	}
	return out
}

// Upstreams rename path parameters routinely. The endpoint is unchanged, so a
// rename must not be reported as a removed path, a removed parameter, or a new
// required parameter -- the last of which is a breaking signal and would raise a
// false alarm on every caller of the path.
func TestParameterRenameIsNotABreakingChange(t *testing.T) {
	t.Parallel()
	const before = `
openapi: 3.0.0
info: {version: 1.0.0}
paths:
  /keys/{keyNumberOrProductKey}/sso:
    post:
      parameters:
        - {name: keyNumberOrProductKey, in: path, required: true, schema: {type: string}}
      responses: {"200": {description: ok}}
`
	const after = `
openapi: 3.0.0
info: {version: 1.0.0}
paths:
  /keys/{keyNumberOrActivationCode}/sso:
    post:
      parameters:
        - {name: keyNumberOrActivationCode, in: path, required: true, schema: {type: string}}
      responses: {"200": {description: ok}}
`
	b, err := Parse([]byte(before))
	if err != nil {
		t.Fatal(err)
	}
	h, err := Parse([]byte(after))
	if err != nil {
		t.Fatal(err)
	}
	changes := Diff(b, h)

	for _, c := range changes {
		if c.Breaking {
			t.Errorf("a parameter rename produced a breaking change: %s (%s)", c.Kind, c.Detail)
		}
		switch c.Kind {
		case SignalPathRemoved, SignalOperationRemoved, SignalParamRemoved, SignalRequiredParamAdded:
			t.Errorf("unexpected %s for a pure rename: %s", c.Kind, c.Detail)
		}
	}
	var renamed bool
	for _, c := range changes {
		if c.Kind == SignalParamRenamed {
			renamed = true
			if c.Before != "/keys/{keyNumberOrProductKey}/sso" || c.After != "/keys/{keyNumberOrActivationCode}/sso" {
				t.Errorf("rename should name both spellings, got %q -> %q", c.Before, c.After)
			}
		}
	}
	if !renamed {
		t.Errorf("want a %s change, got %+v", SignalParamRenamed, kinds(changes))
	}
}

// A genuine removal must still be reported as breaking.
func TestRealPathRemovalIsStillBreaking(t *testing.T) {
	t.Parallel()
	const before = `
openapi: 3.0.0
info: {version: 1.0.0}
paths:
  /keys/{id}/sso:
    post:
      responses: {"200": {description: ok}}
  /keys/{id}:
    get:
      responses: {"200": {description: ok}}
`
	const after = `
openapi: 3.0.0
info: {version: 1.0.0}
paths:
  /keys/{id}:
    get:
      responses: {"200": {description: ok}}
`
	b, _ := Parse([]byte(before))
	h, _ := Parse([]byte(after))
	var found bool
	for _, c := range Diff(b, h) {
		if c.Kind == SignalPathRemoved && c.Breaking {
			found = true
		}
	}
	if !found {
		t.Error("a genuinely removed path must still be reported as breaking")
	}
}
