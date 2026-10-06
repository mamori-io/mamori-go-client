package mamori

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Credential reset option names.
const (
	CredentialResetDays = "CREDENTIALRESETDAYS"
	CredentialRole      = "CREDENTIALROLE"
)

// FilterOperation is a comparison used in search filters.
type FilterOperation string

// Search filter operations.
const (
	FilterEqualsString       FilterOperation = "equals"
	FilterContains           FilterOperation = "contains"
	FilterNotContains        FilterOperation = "notcontains"
	FilterStartsWith         FilterOperation = "startswith"
	FilterEndsWith           FilterOperation = "endswith"
	FilterIsBlank            FilterOperation = "isblank"
	FilterIsNotBlank         FilterOperation = "isnotblank"
	FilterGreaterThan        FilterOperation = ">"
	FilterLessThan           FilterOperation = "<"
	FilterGreaterThanOrEqual FilterOperation = ">="
	FilterLessThanOrEqual    FilterOperation = "<="
	FilterEquals             FilterOperation = "="
	FilterNotEqual           FilterOperation = "<>"
)

// Filter is a single search condition: column, operation, value.
type Filter struct {
	Column    string
	Operation FilterOperation
	Value     any
}

// F is shorthand for constructing a [Filter].
func F(column string, op FilterOperation, value any) Filter {
	return Filter{Column: column, Operation: op, Value: value}
}

func (f Filter) toArray() []any {
	return []any{f.Column, string(f.Operation), f.Value}
}

// Filters is a conjunction of search conditions.
type Filters []Filter

// encode returns the filters in the indexed-object form the search endpoints
// expect ({"0": [col, op, val], "1": ...}), or nil when empty.
func (fs Filters) encode() map[string]any {
	if len(fs) == 0 {
		return nil
	}
	out := make(map[string]any, len(fs))
	for i, f := range fs {
		out[strconv.Itoa(i)] = f.toArray()
	}
	return out
}

// GridFilter builds a DevExtreme-style grid filter expression, as used by some
// search endpoints: a single condition is [col, op, val]; several are joined
// as [cond, "and", cond, ...].
func (fs Filters) GridFilter() []any {
	switch len(fs) {
	case 0:
		return nil
	case 1:
		return fs[0].toArray()
	}
	var out []any
	for i, f := range fs {
		if i > 0 {
			out = append(out, "and")
		}
		out = append(out, f.toArray())
	}
	return out
}

// SearchOptions are paging and filter options for search endpoints.
type SearchOptions struct {
	Skip   int
	Take   int
	Filter Filters
}

func (o SearchOptions) params() Params {
	p := Params{"skip": o.Skip, "take": o.Take}
	if f := o.Filter.encode(); f != nil {
		p["filter"] = f
	}
	return p
}

// SearchResult is the common envelope returned by search endpoints.
type SearchResult[T any] struct {
	Data       []T   `json:"data"`
	TotalCount Count `json:"totalCount"`
}

// Count is a row count. Servers report counts as a JSON number, a numeric
// string, or a single query row such as [{"a1":"0"}]; all decode to an int.
type Count int

// UnmarshalJSON implements [json.Unmarshaler].
func (c *Count) UnmarshalJSON(b []byte) error {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	for {
		switch t := v.(type) {
		case nil:
			*c = 0
			return nil
		case float64:
			*c = Count(t)
			return nil
		case string:
			n, err := strconv.Atoi(strings.TrimSpace(t))
			if err != nil {
				return fmt.Errorf("mamori: invalid count %q", t)
			}
			*c = Count(n)
			return nil
		case []any:
			if len(t) == 0 {
				*c = 0
				return nil
			}
			v = t[0]
		case map[string]any:
			if len(t) != 1 {
				return fmt.Errorf("mamori: invalid count %s", b)
			}
			for _, x := range t {
				v = x
			}
		default:
			return fmt.Errorf("mamori: invalid count %s", b)
		}
	}
}

// SQLEscape escapes single quotes for embedding s in a SQL string literal.
func SQLEscape(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

// checkSQLIdentifier rejects names that cannot safely be embedded unquoted in
// SQL (user names may contain letters, digits, '_', '.', '@' and '-').
func checkSQLIdentifier(name string) error {
	if name == "" {
		return errors.New("mamori: empty identifier")
	}
	for _, r := range name {
		if !(r == '_' || r == '.' || r == '@' || r == '-' ||
			r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return fmt.Errorf("mamori: invalid identifier %q", name)
		}
	}
	return nil
}

// checkSQLNumber rejects ids that are not plain integers.
func checkSQLNumber(id string) error {
	if _, err := strconv.ParseInt(id, 10, 64); err != nil {
		return fmt.Errorf("mamori: invalid id %q", id)
	}
	return nil
}

// sqlQuote returns s as a quoted SQL string literal.
func sqlQuote(s string) string {
	return "'" + SQLEscape(s) + "'"
}

// HexToString decodes a hex string into the bytes it represents.
func HexToString(h string) (string, error) {
	b, err := hex.DecodeString(h)
	return string(b), err
}

// Base64Encode returns the standard base64 encoding of s.
func Base64Encode(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// Base64Decode decodes a standard base64 string.
func Base64Decode(s string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	return string(b), err
}

// AddUniqueExtension appends a time-based _HHMMSS suffix to value, to make
// identifiers unique across test runs.
func AddUniqueExtension(value string) string {
	return value + "_" + time.Now().Format("150405")
}

// Message is a decoded guacamole-style tunnel instruction.
type Message struct {
	Command string
	Params  []string
}

// DecodeMessage decodes a length-prefixed tunnel instruction of the form
// "4.size,1.0,3.640,3.480;".
func DecodeMessage(s string) (Message, error) {
	var parts []string
	i := 0
	for i < len(s) {
		n := 0
		start := i
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			n = n*10 + int(s[i]-'0')
			i++
		}
		if i >= len(s) || s[i] != '.' || i == start {
			if i < len(s) {
				return Message{}, fmt.Errorf("mamori: expected a number or a dot, got %q at %d", s[i], i+1)
			}
			return Message{}, errors.New("mamori: unexpected end of data")
		}
		i++
		// Lengths are in characters (UTF-16 code units in the JS original);
		// walk runes so multi-byte text is handled.
		r := []rune(s[i:])
		if n > len(r) {
			return Message{}, errors.New("mamori: unexpected end of data")
		}
		part := string(r[:n])
		parts = append(parts, part)
		i += len(part)
		if i >= len(s) {
			break
		}
		switch s[i] {
		case ',':
			i++
		case ';':
			i++
			if i < len(s) {
				return Message{}, errors.New("mamori: unexpected data after terminator")
			}
		default:
			return Message{}, fmt.Errorf("mamori: expected comma or semicolon, got %q at %d", s[i], i+1)
		}
	}
	if len(parts) == 0 {
		return Message{}, nil
	}
	return Message{Command: parts[0], Params: parts[1:]}, nil
}
