package verifier

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"regexp"
	"strings"
	"unicode/utf8"
)

// This is format data, not verification code from a bundle. Keep the shipped
// snapshot in sync with the public event schema when adding format support.
//
//go:embed event-v2.schema.json
var eventSchemaBytes []byte
var eventSchema = func() map[string]any {
	var s map[string]any
	if err := json.Unmarshal(eventSchemaBytes, &s); err != nil {
		panic(err)
	}
	return s
}()

// ValidateEvent implements the JSON Schema keywords used by the frozen v2
// schema, including conditional per-event payload schemas and local references.
func ValidateEvent(event map[string]any) error {
	return validateSchema(event, eventSchema, eventSchema, "event", 0)
}

func schemaType(v any, typ string) bool {
	switch typ {
	case "null":
		return v == nil
	case "object":
		_, ok := v.(map[string]any)
		return ok
	case "array":
		_, ok := v.([]any)
		return ok
	case "string":
		_, ok := v.(string)
		return ok
	case "boolean":
		_, ok := v.(bool)
		return ok
	case "integer", "number":
		n, ok := v.(json.Number)
		if !ok {
			return false
		}
		f, err := n.Float64()
		return err == nil && !math.IsInf(f, 0) && (typ == "number" || !strings.ContainsAny(string(n), ".eE"))
	}
	return false
}
func schemaEqual(a, b any) bool {
	if n, ok := a.(json.Number); ok {
		f, e := n.Float64()
		if q, ok := b.(float64); ok {
			return e == nil && f == q
		}
	}
	return reflect.DeepEqual(a, b)
}
func validateSchema(v any, raw any, root map[string]any, where string, depth int) error {
	fail := func(reason string) error { return fmt.Errorf("%s: %s", where, reason) }
	if depth > 100 {
		return fail("schema recursion limit")
	}
	if b, ok := raw.(bool); ok {
		if b {
			return nil
		}
		return fail("forbidden value")
	}
	s, ok := raw.(map[string]any)
	if !ok {
		return fail("invalid verifier schema")
	}
	check := func(x any) error { return validateSchema(v, x, root, where, depth+1) }
	if ref, ok := s["$ref"].(string); ok {
		if !strings.HasPrefix(ref, "#/$defs/") {
			return fail("unsupported schema reference")
		}
		def := root["$defs"].(map[string]any)[strings.TrimPrefix(ref, "#/$defs/")]
		if err := check(def); err != nil {
			return err
		}
	}
	if t, ok := s["type"]; ok {
		valid := false
		switch t := t.(type) {
		case string:
			valid = schemaType(v, t)
		case []any:
			for _, typ := range t {
				if schemaType(v, typ.(string)) {
					valid = true
				}
			}
		}
		if !valid {
			return fail("wrong value type")
		}
	}
	if c, ok := s["const"]; ok && !schemaEqual(v, c) {
		return fail("wrong constant")
	}
	if a, ok := s["enum"].([]any); ok {
		found := false
		for _, x := range a {
			if schemaEqual(v, x) {
				found = true
			}
		}
		if !found {
			return fail("value outside enum")
		}
	}
	if a, ok := s["allOf"].([]any); ok {
		for _, x := range a {
			if err := check(x); err != nil {
				return err
			}
		}
	}
	if a, ok := s["oneOf"].([]any); ok {
		n := 0
		for _, x := range a {
			if check(x) == nil {
				n++
			}
		}
		if n != 1 {
			return fail("oneOf must match exactly once")
		}
	}
	if cond, ok := s["if"]; ok && check(cond) == nil {
		if then, ok := s["then"]; ok {
			if err := check(then); err != nil {
				return err
			}
		}
	}
	if str, ok := v.(string); ok {
		n := float64(utf8.RuneCountInString(str))
		if lo, ok := s["minLength"].(float64); ok && n < lo {
			return fail("string too short")
		}
		if hi, ok := s["maxLength"].(float64); ok && n > hi {
			return fail("string too long")
		}
		if pattern, ok := s["pattern"].(string); ok {
			r, err := regexp.Compile(pattern)
			if err != nil {
				return fail("unsupported schema pattern")
			}
			if !r.MatchString(str) {
				return fail("string pattern mismatch")
			}
		}
	}
	if n, ok := v.(json.Number); ok {
		f, err := n.Float64()
		if err != nil {
			return fail("invalid number")
		}
		if lo, ok := s["minimum"].(float64); ok && f < lo {
			return fail("number below minimum")
		}
		if hi, ok := s["maximum"].(float64); ok && f > hi {
			return fail("number above maximum")
		}
	}
	if a, ok := v.([]any); ok {
		if lo, ok := s["minItems"].(float64); ok && float64(len(a)) < lo {
			return fail("array too short")
		}
		if hi, ok := s["maxItems"].(float64); ok && float64(len(a)) > hi {
			return fail("array too long")
		}
		if items, ok := s["items"]; ok {
			for i, x := range a {
				if err := validateSchema(x, items, root, fmt.Sprintf("%s[%d]", where, i), depth+1); err != nil {
					return err
				}
			}
		}
	}
	if m, ok := v.(map[string]any); ok {
		if required, ok := s["required"].([]any); ok {
			for _, key := range required {
				if _, found := m[key.(string)]; !found {
					return fail("missing " + key.(string))
				}
			}
		}
		props, _ := s["properties"].(map[string]any)
		for key, x := range m {
			if names, ok := s["propertyNames"]; ok {
				if err := validateSchema(key, names, root, where+" key", depth+1); err != nil {
					return err
				}
			}
			if rule, ok := props[key]; ok {
				if err := validateSchema(x, rule, root, where+"."+key, depth+1); err != nil {
					return err
				}
			} else if rule, ok := s["additionalProperties"]; ok {
				if err := validateSchema(x, rule, root, where+"."+key, depth+1); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
