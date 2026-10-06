package mamori

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

// EncodeParams encodes v as a query string in the same format jQuery's
// $.param produces, which is what the mamori server expects for GET and
// DELETE parameters. Nested objects become a[b]=c, arrays of scalars a[]=x and
// arrays of objects a[0][b]=c. Object keys are emitted in sorted order.
//
// v may be any value that marshals to a JSON object (a map or struct).
func EncodeParams(v any) (string, error) {
	return encodeQuery(v)
}

func encodeQuery(v any) (string, error) {
	if v == nil {
		return "", nil
	}
	var generic any
	switch t := v.(type) {
	case url.Values:
		return t.Encode(), nil
	default:
		buf, err := json.Marshal(v)
		if err != nil {
			return "", fmt.Errorf("mamori: encoding query: %w", err)
		}
		if err := json.Unmarshal(buf, &generic); err != nil {
			return "", fmt.Errorf("mamori: encoding query: %w", err)
		}
	}
	obj, ok := generic.(map[string]any)
	if !ok {
		if generic == nil {
			return "", nil
		}
		return "", fmt.Errorf("mamori: query parameters must be an object, got %T", v)
	}

	var parts []string
	add := func(k string, val any) {
		parts = append(parts, escapeComponent(k)+"="+escapeComponent(scalarString(val)))
	}
	for _, k := range slices.Sorted(maps.Keys(obj)) {
		buildParams(k, obj[k], add)
	}
	return strings.Join(parts, "&"), nil
}

func buildParams(prefix string, v any, add func(string, any)) {
	switch t := v.(type) {
	case []any:
		for i, item := range t {
			idx := ""
			if isComposite(item) {
				idx = strconv.Itoa(i)
			}
			buildParams(prefix+"["+idx+"]", item, add)
		}
	case []string:
		for _, item := range t {
			add(prefix+"[]", item)
		}
	case map[string]any:
		for _, k := range slices.Sorted(maps.Keys(t)) {
			buildParams(prefix+"["+k+"]", t[k], add)
		}
	default:
		add(prefix, v)
	}
}

func isComposite(v any) bool {
	switch v.(type) {
	case []any, []string, map[string]any:
		return true
	}
	return false
}

func scalarString(v any) string {
	switch t := v.(type) {
	case nil:
		// JavaScript's encodeURIComponent(null) yields "null".
		return "null"
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case json.Number:
		return t.String()
	default:
		return fmt.Sprint(t)
	}
}

// escapeComponent matches JavaScript's encodeURIComponent.
func escapeComponent(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' ||
			strings.IndexByte("-_.!~*'()", ch) >= 0 {
			b.WriteByte(ch)
		} else {
			fmt.Fprintf(&b, "%%%02X", ch)
		}
	}
	return b.String()
}
