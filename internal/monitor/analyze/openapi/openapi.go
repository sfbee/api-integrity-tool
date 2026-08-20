// Package openapi structurally diffs two OpenAPI documents.
//
// This is the highest-signal analysis the monitor has, and the only one
// available for the common case of a third-party API whose implementation is
// closed but whose specification is public.
//
// It compares parsed documents rather than diff text, for two reasons. GitHub
// omits the patch for large files, so a unified diff of a real specification is
// often simply absent. And even when present, a textual diff cannot tell that a
// parameter moved from optional to required, which is exactly the change that
// breaks a caller.
//
// The document is walked as generic maps rather than through a typed model, so
// 2.0, 3.0 and 3.1 all work, unknown extensions are ignored rather than
// rejected, and a malformed file degrades to "unparseable" instead of a panic.
package openapi

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// OpKey identifies one operation.
type OpKey struct {
	Method string
	Path   string
}

func (k OpKey) String() string { return k.Method + " " + k.Path }

// Param is one request parameter.
type Param struct {
	Name     string
	In       string
	Required bool
	Type     string
	Enum     []string
}

// Operation is the part of an operation that can break a caller.
type Operation struct {
	Key        OpKey
	Deprecated bool
	Sunset     string
	Params     map[string]Param
	// BodyRequired records whether a request body must be sent.
	BodyRequired bool
	// BodyRequiredProps are the required properties of the request body.
	BodyRequiredProps map[string]bool
	// ResponseFields maps a status code to the properties of its schema, with
	// the value recording whether the property is required.
	ResponseFields map[string]map[string]bool
	Statuses       []string
	Security       []string
	HasSecurity    bool
}

// Doc is a parsed specification.
type Doc struct {
	SpecVersion string
	InfoVersion string
	Servers     []string
	Operations  map[OpKey]*Operation
	Security    []string
	Paths       map[string]bool
}

var methods = []string{"get", "put", "post", "delete", "options", "head", "patch", "trace"}

// Parse reads an OpenAPI or Swagger document in YAML or JSON. JSON is valid
// YAML, so one parser serves both.
func Parse(data []byte) (doc *Doc, err error) {
	// A specification is untrusted input from another repository. A panic in
	// parsing must degrade to an error, never take down a check.
	defer func() {
		if r := recover(); r != nil {
			doc, err = nil, fmt.Errorf("malformed specification: %v", r)
		}
	}()

	var root map[string]any
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("parse specification: %w", err)
	}
	if root == nil {
		return nil, fmt.Errorf("empty specification")
	}
	d := &Doc{
		Operations: map[OpKey]*Operation{},
		Paths:      map[string]bool{},
	}
	d.SpecVersion = str(root["openapi"])
	if d.SpecVersion == "" {
		d.SpecVersion = str(root["swagger"])
	}
	if d.SpecVersion == "" {
		return nil, fmt.Errorf("not an OpenAPI or Swagger document")
	}
	if info, ok := root["info"].(map[string]any); ok {
		d.InfoVersion = str(info["version"])
	}
	d.Servers = parseServers(root)
	d.Security = securityNames(root["security"])

	paths, _ := root["paths"].(map[string]any)
	basePath := str(root["basePath"])
	for rawPath, v := range paths {
		item, ok := v.(map[string]any)
		if !ok {
			continue
		}
		p := basePath + rawPath
		d.Paths[p] = true
		// Parameters declared on the path item apply to every operation on it.
		shared := parseParams(root, item["parameters"])
		for _, m := range methods {
			opRaw, ok := item[m].(map[string]any)
			if !ok {
				continue
			}
			key := OpKey{Method: strings.ToUpper(m), Path: p}
			d.Operations[key] = parseOperation(root, key, opRaw, shared)
		}
	}
	return d, nil
}

func parseServers(root map[string]any) []string {
	var out []string
	if servers, ok := root["servers"].([]any); ok {
		for _, s := range servers {
			if m, ok := s.(map[string]any); ok {
				if u := str(m["url"]); u != "" {
					out = append(out, u)
				}
			}
		}
	}
	// Swagger 2.0 spells it host plus basePath.
	if host := str(root["host"]); host != "" {
		out = append(out, host+str(root["basePath"]))
	}
	sort.Strings(out)
	return out
}

func parseOperation(root map[string]any, key OpKey, op map[string]any, shared map[string]Param) *Operation {
	o := &Operation{
		Key:               key,
		Deprecated:        boolOf(op["deprecated"]),
		Params:            map[string]Param{},
		BodyRequiredProps: map[string]bool{},
		ResponseFields:    map[string]map[string]bool{},
	}
	for k, v := range shared {
		o.Params[k] = v
	}
	for k, v := range parseParams(root, op["parameters"]) {
		o.Params[k] = v
	}
	if s := str(op["x-sunset"]); s != "" {
		o.Sunset = s
	} else if s := str(op["x-deprecated-at"]); s != "" {
		o.Sunset = s
	}

	if body, ok := op["requestBody"].(map[string]any); ok {
		o.BodyRequired = boolOf(body["required"])
		if schema := firstContentSchema(root, body); schema != nil {
			for _, name := range requiredList(schema) {
				o.BodyRequiredProps[name] = true
			}
		}
	}
	// Swagger 2.0 expresses the body as a parameter with in: body.
	for _, p := range o.Params {
		if p.In == "body" && p.Required {
			o.BodyRequired = true
		}
	}

	if responses, ok := op["responses"].(map[string]any); ok {
		for code, rv := range responses {
			o.Statuses = append(o.Statuses, code)
			rm, ok := rv.(map[string]any)
			if !ok {
				continue
			}
			schema := firstContentSchema(root, rm)
			if schema == nil {
				// Swagger 2.0 puts the schema directly on the response.
				schema = resolve(root, rm["schema"])
			}
			if schema == nil {
				continue
			}
			o.ResponseFields[code] = schemaProps(root, schema, 0)
		}
		sort.Strings(o.Statuses)
	}

	if sec, ok := op["security"]; ok {
		o.HasSecurity = true
		o.Security = securityNames(sec)
	}
	return o
}

func parseParams(root map[string]any, v any) map[string]Param {
	out := map[string]Param{}
	list, ok := v.([]any)
	if !ok {
		return out
	}
	for _, e := range list {
		m := resolve(root, e)
		if m == nil {
			continue
		}
		name := str(m["name"])
		if name == "" {
			continue
		}
		p := Param{Name: name, In: str(m["in"]), Required: boolOf(m["required"])}
		if schema := resolve(root, m["schema"]); schema != nil {
			p.Type = str(schema["type"])
			p.Enum = enumValues(schema["enum"])
		} else {
			p.Type = str(m["type"])
			p.Enum = enumValues(m["enum"])
		}
		// A path parameter is required by definition, whatever the file says.
		if p.In == "path" {
			p.Required = true
		}
		out[p.In+":"+p.Name] = p
	}
	return out
}

// firstContentSchema returns the schema of the first media type, which is
// nearly always application/json and is the one a caller depends on.
func firstContentSchema(root map[string]any, holder map[string]any) map[string]any {
	content, ok := holder["content"].(map[string]any)
	if !ok {
		return nil
	}
	keys := make([]string, 0, len(content))
	for k := range content {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	// Prefer JSON when present so the comparison is stable and meaningful.
	for _, k := range keys {
		if strings.Contains(k, "json") {
			if mt, ok := content[k].(map[string]any); ok {
				return resolve(root, mt["schema"])
			}
		}
	}
	for _, k := range keys {
		if mt, ok := content[k].(map[string]any); ok {
			if s := resolve(root, mt["schema"]); s != nil {
				return s
			}
		}
	}
	return nil
}

const maxSchemaDepth = 6

// schemaProps flattens a schema's properties to a name-to-required map. Nested
// objects contribute dotted names, bounded in depth so a recursive schema
// cannot loop forever.
func schemaProps(root map[string]any, schema map[string]any, depth int) map[string]bool {
	out := map[string]bool{}
	if depth > maxSchemaDepth || schema == nil {
		return out
	}
	// Unwrap arrays so a list response is compared by its item shape.
	if str(schema["type"]) == "array" {
		if items := resolve(root, schema["items"]); items != nil {
			return schemaProps(root, items, depth+1)
		}
	}
	for _, key := range []string{"allOf", "oneOf", "anyOf"} {
		if list, ok := schema[key].([]any); ok {
			for _, e := range list {
				if sub := resolve(root, e); sub != nil {
					for k, v := range schemaProps(root, sub, depth+1) {
						out[k] = out[k] || v
					}
				}
			}
		}
	}
	required := map[string]bool{}
	for _, name := range requiredList(schema) {
		required[name] = true
	}
	props, ok := schema["properties"].(map[string]any)
	if !ok {
		return out
	}
	for name, pv := range props {
		out[name] = required[name]
		sub := resolve(root, pv)
		if sub == nil {
			continue
		}
		if str(sub["type"]) == "object" || sub["properties"] != nil {
			for k, v := range schemaProps(root, sub, depth+1) {
				out[name+"."+k] = v
			}
		}
	}
	return out
}

func requiredList(schema map[string]any) []string {
	list, ok := schema["required"].([]any)
	if !ok {
		return nil
	}
	var out []string
	for _, e := range list {
		if s := str(e); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// resolve follows a local $ref. Remote refs are deliberately not fetched: it
// would make analysis non-hermetic and turn a specification into an SSRF
// vector.
func resolve(root map[string]any, v any) map[string]any {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	for i := 0; i < 10; i++ {
		ref := str(m["$ref"])
		if ref == "" {
			return m
		}
		if !strings.HasPrefix(ref, "#/") {
			return nil
		}
		cur := any(root)
		for _, part := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
			part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
			node, ok := cur.(map[string]any)
			if !ok {
				return nil
			}
			cur = node[part]
		}
		next, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		m = next
	}
	return m
}

func securityNames(v any) []string {
	list, ok := v.([]any)
	if !ok {
		return nil
	}
	var out []string
	for _, e := range list {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		for name, scopes := range m {
			entry := name
			if ss := enumValues(scopes); len(ss) > 0 {
				entry += "[" + strings.Join(ss, ",") + "]"
			}
			out = append(out, entry)
		}
	}
	sort.Strings(out)
	return out
}

func enumValues(v any) []string {
	list, ok := v.([]any)
	if !ok {
		return nil
	}
	var out []string
	for _, e := range list {
		out = append(out, str(e))
	}
	sort.Strings(out)
	return out
}

func str(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case nil:
		return ""
	case bool:
		if t {
			return "true"
		}
		return "false"
	default:
		return fmt.Sprintf("%v", t)
	}
}

func boolOf(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return t == "true"
	default:
		return false
	}
}
