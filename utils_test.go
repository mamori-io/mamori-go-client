package mamori

import (
	"encoding/json"
	"testing"
)

func TestCountUnmarshal(t *testing.T) {
	for in, want := range map[string]Count{
		`5`: 5, `"7"`: 7, `[{"a1":"3"}]`: 3, `[]`: 0, `null`: 0, `[{"n":4}]`: 4,
	} {
		var r SearchResult[Params]
		if err := json.Unmarshal([]byte(`{"data":[],"totalCount":`+in+`}`), &r); err != nil || r.TotalCount != want {
			t.Errorf("totalCount %s = %d, %v; want %d", in, r.TotalCount, err, want)
		}
	}
	var c Count
	if err := json.Unmarshal([]byte(`"x"`), &c); err == nil {
		t.Error("expected error for non-numeric count")
	}
}
