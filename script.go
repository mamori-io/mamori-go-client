package mamori

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// ScriptTargetType is where a script runs.
type ScriptTargetType string

// Script target types.
const (
	// ScriptTargetMamori scripts are JavaScript run by the mamori server.
	ScriptTargetMamori ScriptTargetType = "MAMORI"
	// ScriptTargetSQL scripts are SQL run against a datasource.
	ScriptTargetSQL ScriptTargetType = "SQL"
)

// ScriptParamType is the data type of a script parameter.
type ScriptParamType string

// Script parameter types.
const (
	ScriptParamTypeString    ScriptParamType = "string"
	ScriptParamTypeNumber    ScriptParamType = "number"
	ScriptParamTypeBoolean   ScriptParamType = "boolean"
	ScriptParamTypeDatetime  ScriptParamType = "datetime"
	ScriptParamTypeJSONArray ScriptParamType = "json_array"
	ScriptParamTypePassword  ScriptParamType = "password"
	ScriptParamTypeCSVFile   ScriptParamType = "csv_file"
	ScriptParamTypeList      ScriptParamType = "list"
	ScriptParamTypeMSQLList  ScriptParamType = "msql_list"
)

// ScriptParamDirection is the direction of a script parameter.
type ScriptParamDirection string

// Script parameter directions.
const (
	ScriptParamIn    ScriptParamDirection = "in"
	ScriptParamOut   ScriptParamDirection = "out"
	ScriptParamInOut ScriptParamDirection = "inout"
)

// ScriptParameter declares an input or output of a script.
type ScriptParameter struct {
	Name      string               `json:"name"`
	Direction ScriptParamDirection `json:"direction"`
	Type      ScriptParamType      `json:"type"`
	Default   any                  `json:"default,omitempty"`
	// Items are the static choices for type list.
	Items []string `json:"items,omitempty"`
	// SQL is an MSQL query returning Text, Value columns for type msql_list.
	SQL string `json:"sql,omitempty"`
	// Hint is an optional UI hint for list and msql_list parameters.
	Hint string `json:"hint,omitempty"`
}

// Script is a stored, parameterised script that can be run on demand.
type Script struct {
	ID         int64            `json:"id,omitempty"`
	Name       string           `json:"name"`
	TargetType ScriptTargetType `json:"target_type"`
	// TargetName is the datasource for SQL scripts; empty means none.
	TargetName string            `json:"target_name"`
	Language   string            `json:"language"`
	Body       string            `json:"body"`
	Parameters []ScriptParameter `json:"parameters"`
	// Capabilities lists the high-risk mamori.* operations the script may
	// use. nil means unrestricted; an empty non-nil slice denies all of them.
	Capabilities []string `json:"capabilities"`
}

// NewScript returns a script. targetType defaults to [ScriptTargetMamori];
// the language is derived from it.
func NewScript(name string, targetType ScriptTargetType, body string) *Script {
	s := &Script{Name: name, Body: body, Parameters: []ScriptParameter{}}
	s.SetTarget(targetType, "")
	return s
}

// SetTarget sets the target type and name, and the matching language
// (text/javascript for MAMORI, text/sql otherwise).
func (sc *Script) SetTarget(targetType ScriptTargetType, targetName string) {
	if targetType == "" {
		targetType = ScriptTargetMamori
	}
	sc.TargetType = targetType
	sc.TargetName = targetName
	if targetType == ScriptTargetMamori {
		sc.Language = "text/javascript"
	} else {
		sc.Language = "text/sql"
	}
}

// scriptCol looks a column up by name, then upper-case, then lower-case.
func scriptCol(row map[string]any, name string) any {
	if row == nil {
		return nil
	}
	if v, ok := row[name]; ok {
		return v
	}
	if v, ok := row[strings.ToUpper(name)]; ok {
		return v
	}
	if v, ok := row[strings.ToLower(name)]; ok {
		return v
	}
	return nil
}

// scriptString converts a column value like JavaScript's String().
func scriptString(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// scriptNumber converts a value like JavaScript's Number(), reporting
// whether the result is finite.
func scriptNumber(v any) (int64, bool) {
	var f float64
	switch t := v.(type) {
	case float64:
		f = t
	case json.Number:
		var err error
		if f, err = t.Float64(); err != nil {
			return 0, false
		}
	case string:
		s := strings.TrimSpace(t)
		if s == "" {
			return 0, true
		}
		var err error
		if f, err = strconv.ParseFloat(s, 64); err != nil {
			return 0, false
		}
	case bool:
		if t {
			return 1, true
		}
		return 0, true
	default:
		return 0, false
	}
	if math.IsInf(f, 0) || math.IsNaN(f) {
		return 0, false
	}
	return int64(f), true
}

// scriptDecodeJSONColumn decodes a column that may hold JSON text.
func scriptDecodeJSONColumn(v any) (any, bool) {
	if s, ok := v.(string); ok {
		var out any
		if json.Unmarshal([]byte(s), &out) != nil {
			return nil, false
		}
		return out, true
	}
	return v, true
}

// scriptFromRow builds a Script from a SYS.SCRIPTS row.
func scriptFromRow(row Row) (*Script, error) {
	tt := scriptString(scriptCol(row, "target_type"))
	if tt == "" {
		tt = string(ScriptTargetMamori)
	}
	sc := NewScript(scriptString(scriptCol(row, "name")), ScriptTargetType(strings.ToUpper(tt)), scriptString(scriptCol(row, "body")))
	if id := scriptCol(row, "id"); id != nil {
		sc.ID, _ = scriptNumber(id)
	}
	sc.TargetName = scriptString(scriptCol(row, "target_name"))
	if lang := scriptCol(row, "language"); lang != nil {
		sc.Language = scriptString(lang)
	}
	sc.Parameters = []ScriptParameter{}
	if p, ok := scriptDecodeJSONColumn(scriptCol(row, "parameters")); ok {
		if arr, ok := p.([]any); ok {
			buf, err := json.Marshal(arr)
			if err != nil {
				return nil, err
			}
			if err := json.Unmarshal(buf, &sc.Parameters); err != nil {
				return nil, fmt.Errorf("mamori: decoding script parameters: %w", err)
			}
		}
	}
	sc.Capabilities = nil
	if c, ok := scriptDecodeJSONColumn(scriptCol(row, "capabilities")); ok {
		if arr, ok := c.([]any); ok {
			sc.Capabilities = make([]string, 0, len(arr))
			for _, x := range arr {
				sc.Capabilities = append(sc.Capabilities, scriptString(x))
			}
		}
	}
	return sc, nil
}

// scriptFirstRow returns the first row of a procedure response: the first
// element of an array, of .data or of .rows, or the response itself.
func scriptFirstRow(raw json.RawMessage) any {
	var v any
	if json.Unmarshal(raw, &v) != nil || v == nil {
		return nil
	}
	first := func(a []any) any {
		if len(a) == 0 {
			return nil
		}
		return a[0]
	}
	switch t := v.(type) {
	case []any:
		return first(t)
	case map[string]any:
		if a, ok := t["data"].([]any); ok {
			return first(a)
		}
		if a, ok := t["rows"].([]any); ok {
			return first(a)
		}
	}
	return v
}

// scriptExtractID extracts the id of a newly created object from a
// procedure response.
func scriptExtractID(raw json.RawMessage) (int64, bool) {
	row := scriptFirstRow(raw)
	switch t := row.(type) {
	case nil:
		return 0, false
	case map[string]any:
		v := scriptCol(t, "result")
		if v == nil {
			v = scriptCol(t, "id")
		}
		if v == nil && len(t) == 1 {
			for _, x := range t {
				v = x
			}
		}
		if v == nil {
			return 0, false
		}
		return scriptNumber(v)
	}
	return scriptNumber(row)
}

// ScriptRunResult is the outcome of running a script or script flow.
type ScriptRunResult struct {
	// Success reports whether the run succeeded.
	Success bool
	// Result is the decoded result (for example {"outs": {...}}).
	Result any
	// Error is the error reported by the server, if any.
	Error any
	// Raw is the complete server response.
	Raw json.RawMessage
}

// Outs returns Result["outs"] when the result is an object.
func (r *ScriptRunResult) Outs() map[string]any {
	m, _ := r.Result.(map[string]any)
	outs, _ := m["outs"].(map[string]any)
	return outs
}

// scriptRunResult converts a RUN_SCRIPT / RUN_SCRIPT_FLOW response.
func scriptRunResult(raw json.RawMessage) *ScriptRunResult {
	out := &ScriptRunResult{Raw: raw}
	row, ok := scriptFirstRow(raw).(map[string]any)
	if !ok {
		return out
	}
	switch s := scriptCol(row, "success").(type) {
	case bool:
		out.Success = s
	case string:
		out.Success = s == "true"
	}
	out.Result = scriptCol(row, "result")
	if s, ok := out.Result.(string); ok {
		var v any
		if json.Unmarshal([]byte(s), &v) == nil {
			out.Result = v
		}
	}
	out.Error = scriptCol(row, "error")
	return out
}

func scriptJSON(v any) (string, error) {
	b, err := json.Marshal(v)
	return string(b), err
}

func (sc *Script) procedureArgs() ([]any, error) {
	params := sc.Parameters
	if params == nil {
		params = []ScriptParameter{}
	}
	p, err := scriptJSON(params)
	if err != nil {
		return nil, err
	}
	var caps any
	if sc.Capabilities != nil {
		if caps, err = scriptJSON(sc.Capabilities); err != nil {
			return nil, err
		}
	}
	var target any
	if sc.TargetName != "" {
		target = sc.TargetName
	}
	return []any{sc.Name, sc.TargetType, target, sc.Body, p, caps}, nil
}

// List returns all scripts visible to the user, ordered by name.
func (s *ScriptService) List(ctx context.Context) ([]*Script, error) {
	rows, err := s.client.Select(ctx, "SELECT * FROM SYS.SCRIPTS ORDER BY name")
	if err != nil {
		return nil, err
	}
	out := make([]*Script, 0, len(rows))
	for _, r := range rows {
		sc, err := scriptFromRow(r)
		if err != nil {
			return nil, err
		}
		out = append(out, sc)
	}
	return out, nil
}

// GetByName returns the script with the given name (case-insensitive), or
// [ErrNotFound].
func (s *ScriptService) GetByName(ctx context.Context, name string) (*Script, error) {
	rows, err := s.client.Select(ctx, "SELECT * FROM SYS.SCRIPTS WHERE lower(name) = lower("+sqlQuote(name)+")")
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("mamori: script %q: %w", name, ErrNotFound)
	}
	return scriptFromRow(rows[0])
}

// Create creates the script and, when the response carries it, stores the
// new id in sc.ID.
func (s *ScriptService) Create(ctx context.Context, sc *Script) (json.RawMessage, error) {
	args, err := sc.procedureArgs()
	if err != nil {
		return nil, err
	}
	raw, err := s.client.CallProcedure(ctx, "CREATE_SCRIPT", args...)
	if err != nil {
		return nil, err
	}
	if id, ok := scriptExtractID(raw); ok {
		sc.ID = id
	}
	return raw, nil
}

// Update saves the script sc.ID.
func (s *ScriptService) Update(ctx context.Context, sc *Script) (json.RawMessage, error) {
	if sc.ID == 0 {
		return nil, errors.New("mamori: script id is required for update")
	}
	args, err := sc.procedureArgs()
	if err != nil {
		return nil, err
	}
	return s.client.CallProcedure(ctx, "UPDATE_SCRIPT", append([]any{sc.ID}, args...)...)
}

// Delete deletes the script with the given id.
func (s *ScriptService) Delete(ctx context.Context, id int64) (json.RawMessage, error) {
	if id == 0 {
		return nil, errors.New("mamori: script id is required for delete")
	}
	return s.client.CallProcedure(ctx, "DELETE_SCRIPT", id)
}

// Run runs the named script with the given inputs (may be nil).
func (s *ScriptService) Run(ctx context.Context, name string, inputs map[string]any) (*ScriptRunResult, error) {
	if inputs == nil {
		inputs = map[string]any{}
	}
	in, err := scriptJSON(inputs)
	if err != nil {
		return nil, err
	}
	raw, err := s.client.CallProcedure(ctx, "RUN_SCRIPT", name, in)
	if err != nil {
		return nil, err
	}
	return scriptRunResult(raw), nil
}

// GrantTo grants EXECUTE SCRIPT on the named script to grantee.
func (s *ScriptService) GrantTo(ctx context.Context, name, grantee string) error {
	_, err := s.client.Permissions.Grant(ctx, NewScriptPermission(name, grantee))
	return err
}

// RevokeFrom revokes EXECUTE SCRIPT on the named script from grantee.
func (s *ScriptService) RevokeFrom(ctx context.Context, name, grantee string) error {
	_, err := s.client.Permissions.Revoke(ctx, NewScriptPermission(name, grantee))
	return err
}
