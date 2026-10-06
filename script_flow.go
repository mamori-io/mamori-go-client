package mamori

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

// ScriptFlowStepType is the kind of a script flow step.
type ScriptFlowStepType string

// Script flow step types.
const (
	ScriptFlowStepScript ScriptFlowStepType = "script"
	ScriptFlowStepLoop   ScriptFlowStepType = "loop"
	ScriptFlowStepFilter ScriptFlowStepType = "filter"
)

// ScriptFlowStepMode is how a loop step runs its iterations.
type ScriptFlowStepMode string

// Script flow loop modes.
const (
	ScriptFlowModeSerial   ScriptFlowStepMode = "serial"
	ScriptFlowModeParallel ScriptFlowStepMode = "parallel"
)

// ScriptFlowFilterMethod is how a filter step selects rows.
type ScriptFlowFilterMethod string

// Script flow filter methods.
const (
	ScriptFlowFilterFirstN  ScriptFlowFilterMethod = "first_n"
	ScriptFlowFilterRandomN ScriptFlowFilterMethod = "random_n"
	ScriptFlowFilterColumns ScriptFlowFilterMethod = "columns"
	ScriptFlowFilterScript  ScriptFlowFilterMethod = "script"
)

// ScriptFlowMappingSpec maps a step input to an output of another block.
type ScriptFlowMappingSpec struct {
	// From is the canvas / step block id of the source block.
	From string `json:"from"`
	// Name is the output name on the source block (ROW for loop rows).
	Name string `json:"name"`
}

// ScriptFlowColumnFilter is a column condition of a "columns" filter step.
type ScriptFlowColumnFilter struct {
	Column string `json:"column"`
	Value  string `json:"value,omitempty"`
}

// ScriptFlowStepDef defines one step of a script flow.
type ScriptFlowStepDef struct {
	ID            string                   `json:"id,omitempty"`
	Script        string                   `json:"script,omitempty"`
	Type          ScriptFlowStepType       `json:"type,omitempty"`
	Name          string                   `json:"name,omitempty"`
	Mode          ScriptFlowStepMode       `json:"mode,omitempty"`
	Method        ScriptFlowFilterMethod   `json:"method,omitempty"`
	Count         int                      `json:"count,omitempty"`
	ColumnFilters []ScriptFlowColumnFilter `json:"column_filters,omitempty"`
	// Mappings maps input names to a [ScriptFlowMappingSpec] or a literal
	// value. Mappings read from the server are decoded as generic JSON.
	Mappings map[string]any      `json:"mappings,omitempty"`
	Steps    []ScriptFlowStepDef `json:"steps,omitempty"`
}

// MarshalJSON encodes the step, keeping an explicitly empty (non-nil)
// Mappings map as {} while omitting a nil one.
func (d ScriptFlowStepDef) MarshalJSON() ([]byte, error) {
	type plain ScriptFlowStepDef
	var m *map[string]any
	if d.Mappings != nil {
		m = &d.Mappings
	}
	return json.Marshal(struct {
		plain
		Mappings *map[string]any `json:"mappings,omitempty"`
	}{plain(d), m})
}

// ScriptFlow chains scripts into a flow whose steps pass outputs to inputs.
type ScriptFlow struct {
	ID    int64               `json:"id,omitempty"`
	Name  string              `json:"name"`
	Steps []ScriptFlowStepDef `json:"steps"`
}

// NewScriptFlow returns a script flow with the given steps.
func NewScriptFlow(name string, steps ...ScriptFlowStepDef) *ScriptFlow {
	if steps == nil {
		steps = []ScriptFlowStepDef{}
	}
	return &ScriptFlow{Name: name, Steps: steps}
}

func scriptFlowFromRow(row Row) *ScriptFlow {
	f := NewScriptFlow(scriptString(scriptCol(row, "name")))
	if id := scriptCol(row, "id"); id != nil {
		f.ID, _ = scriptNumber(id)
	}
	return f
}

func (f *ScriptFlow) stepsJSON() (string, error) {
	steps := f.Steps
	if steps == nil {
		steps = []ScriptFlowStepDef{}
	}
	return scriptJSON(steps)
}

// List returns all script flows visible to the user, ordered by name. Steps
// are not loaded; use [ScriptFlowService.GetByName] for those.
func (s *ScriptFlowService) List(ctx context.Context) ([]*ScriptFlow, error) {
	rows, err := s.client.Select(ctx, "SELECT * FROM SYS.SCRIPT_FLOWS ORDER BY name")
	if err != nil {
		return nil, err
	}
	out := make([]*ScriptFlow, 0, len(rows))
	for _, r := range rows {
		out = append(out, scriptFlowFromRow(r))
	}
	return out, nil
}

// GetByName returns the named flow (case-insensitive) with its top-level
// steps (script and mappings), or [ErrNotFound].
func (s *ScriptFlowService) GetByName(ctx context.Context, name string) (*ScriptFlow, error) {
	rows, err := s.client.Select(ctx, "SELECT * FROM SYS.SCRIPT_FLOWS WHERE lower(name) = lower("+sqlQuote(name)+")")
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("mamori: script flow %q: %w", name, ErrNotFound)
	}
	f := scriptFlowFromRow(rows[0])
	steps, err := s.client.Select(ctx, "SELECT * FROM SYS.SCRIPT_FLOW_STEPS WHERE flow_id = "+strconv.FormatInt(f.ID, 10)+" ORDER BY position")
	if err != nil {
		return nil, err
	}
	f.Steps = make([]ScriptFlowStepDef, 0, len(steps))
	for _, st := range steps {
		mappings := map[string]any{}
		if raw := scriptCol(st, "input_mappings"); raw != nil && raw != "" {
			if v, ok := scriptDecodeJSONColumn(raw); ok {
				if m, ok := v.(map[string]any); ok {
					mappings = m
				}
			}
		}
		f.Steps = append(f.Steps, ScriptFlowStepDef{
			Script:   scriptString(scriptCol(st, "script_name")),
			Mappings: mappings,
		})
	}
	return f, nil
}

// Create creates the flow and, when the response carries it, stores the new
// id in f.ID.
func (s *ScriptFlowService) Create(ctx context.Context, f *ScriptFlow) (json.RawMessage, error) {
	steps, err := f.stepsJSON()
	if err != nil {
		return nil, err
	}
	raw, err := s.client.CallProcedure(ctx, "CREATE_SCRIPT_FLOW", f.Name, steps, nil, "[]")
	if err != nil {
		return nil, err
	}
	if id, ok := scriptExtractID(raw); ok {
		f.ID = id
	}
	return raw, nil
}

// Update saves the flow f.ID.
func (s *ScriptFlowService) Update(ctx context.Context, f *ScriptFlow) (json.RawMessage, error) {
	if f.ID == 0 {
		return nil, errors.New("mamori: script flow id is required for update")
	}
	steps, err := f.stepsJSON()
	if err != nil {
		return nil, err
	}
	return s.client.CallProcedure(ctx, "UPDATE_SCRIPT_FLOW", f.ID, f.Name, steps, nil, "[]")
}

// Delete deletes the flow with the given id.
func (s *ScriptFlowService) Delete(ctx context.Context, id int64) (json.RawMessage, error) {
	if id == 0 {
		return nil, errors.New("mamori: script flow id is required for delete")
	}
	return s.client.CallProcedure(ctx, "DELETE_SCRIPT_FLOW", id)
}

// Run runs the named flow with the given inputs (may be nil).
func (s *ScriptFlowService) Run(ctx context.Context, name string, inputs map[string]any) (*ScriptRunResult, error) {
	if inputs == nil {
		inputs = map[string]any{}
	}
	in, err := scriptJSON(inputs)
	if err != nil {
		return nil, err
	}
	raw, err := s.client.CallProcedure(ctx, "RUN_SCRIPT_FLOW", name, in)
	if err != nil {
		return nil, err
	}
	return scriptRunResult(raw), nil
}

// GrantTo grants EXECUTE SCRIPT FLOW on the named flow to grantee.
func (s *ScriptFlowService) GrantTo(ctx context.Context, name, grantee string) error {
	_, err := s.client.Permissions.Grant(ctx, NewScriptFlowPermission(name, grantee))
	return err
}

// RevokeFrom revokes EXECUTE SCRIPT FLOW on the named flow from grantee.
func (s *ScriptFlowService) RevokeFrom(ctx context.Context, name, grantee string) error {
	_, err := s.client.Permissions.Revoke(ctx, NewScriptFlowPermission(name, grantee))
	return err
}
