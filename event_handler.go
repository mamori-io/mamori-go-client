package mamori

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
)

// EventHandlerType is the kind of an event handler.
type EventHandlerType string

// Event handler types.
const (
	EventHandlerTypeTrigger      EventHandlerType = "trigger"
	EventHandlerTypeRule         EventHandlerType = "rule"
	EventHandlerTypePolicyData   EventHandlerType = "policy_data"
	EventHandlerTypeHTTPRequest  EventHandlerType = "http_request"
	EventHandlerTypeHTTPResponse EventHandlerType = "http_response"
	EventHandlerTypeTextFrame    EventHandlerType = "text_frame"
	EventHandlerTypeRequest      EventHandlerType = "request"
)

// EventHandler is a server-side script run in response to events.
type EventHandler struct {
	ID       int64            `json:"id,omitempty"`
	Name     string           `json:"name"`
	Type     EventHandlerType `json:"type"`
	Language string           `json:"language"`
	Body     string           `json:"body"`
	// Capabilities lists the high-risk mamori.* operations the handler may
	// use. nil means legacy unrestricted; an empty non-nil slice denies all
	// of them.
	Capabilities []string `json:"capabilities"`
}

// NewEventHandler returns a JavaScript event handler with no capability
// restrictions.
func NewEventHandler(name string, typ EventHandlerType, body string) *EventHandler {
	return &EventHandler{Name: name, Type: typ, Body: body, Language: "text/javascript"}
}

// UnmarshalJSON decodes a handler record. Capabilities may be a JSON array,
// a JSON-encoded string holding an array, or null/empty.
func (h *EventHandler) UnmarshalJSON(data []byte) error {
	type plain EventHandler
	var rec struct {
		plain
		Capabilities json.RawMessage `json:"capabilities"`
	}
	rec.Language = "text/javascript"
	if err := json.Unmarshal(data, &rec); err != nil {
		return err
	}
	*h = EventHandler(rec.plain)
	h.Capabilities = eventHandlerNormalizeCapabilities(rec.Capabilities)
	return nil
}

// eventHandlerNormalizeCapabilities mirrors the TypeScript normalizeCapabilities.
func eventHandlerNormalizeCapabilities(raw json.RawMessage) []string {
	var v any
	if len(raw) == 0 || json.Unmarshal(raw, &v) != nil {
		return nil
	}
	if s, ok := v.(string); ok {
		if s == "" || json.Unmarshal([]byte(s), &v) != nil {
			return nil
		}
	}
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		switch t := x.(type) {
		case string:
			out = append(out, t)
		case nil:
			out = append(out, "null")
		default:
			b, _ := json.Marshal(t)
			out = append(out, string(b))
		}
	}
	return out
}

func (h *EventHandler) payload(id any) Params {
	p := Params{
		"id":       id,
		"name":     h.Name,
		"type":     h.Type,
		"body":     h.Body,
		"language": h.Language,
	}
	if h.Capabilities != nil {
		p["capabilities"] = h.Capabilities
	}
	return p
}

// List returns event handlers. The server may answer with a plain array, in
// which case TotalCount is the number of rows returned.
func (s *EventHandlerService) List(ctx context.Context, opts SearchOptions) (*SearchResult[EventHandler], error) {
	raw, err := s.client.Call(ctx, http.MethodGet, "/v1/event_handlers", opts.params())
	if err != nil {
		return nil, err
	}
	var arr []EventHandler
	if json.Unmarshal(raw, &arr) == nil {
		return &SearchResult[EventHandler]{Data: arr, TotalCount: Count(len(arr))}, nil
	}
	var res SearchResult[EventHandler]
	if err := decode(raw, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// GetByName returns the event handler with the given name (and type, unless
// typ is empty), or [ErrNotFound]. Only the first 500 handlers are searched.
func (s *EventHandlerService) GetByName(ctx context.Context, name string, typ EventHandlerType) (*EventHandler, error) {
	res, err := s.List(ctx, SearchOptions{Skip: 0, Take: 500})
	if err != nil {
		return nil, err
	}
	for i := range res.Data {
		h := &res.Data[i]
		if h.Name == name && (typ == "" || h.Type == typ) {
			return h, nil
		}
	}
	return nil, fmt.Errorf("mamori: event handler %q: %w", name, ErrNotFound)
}

// Create creates the event handler.
func (s *EventHandlerService) Create(ctx context.Context, h *EventHandler) (json.RawMessage, error) {
	return s.client.Call(ctx, http.MethodPost, "/v1/event_handlers", h.payload(""))
}

// Update saves the event handler h.ID.
func (s *EventHandlerService) Update(ctx context.Context, h *EventHandler) (json.RawMessage, error) {
	return s.client.Call(ctx, http.MethodPut, "/v1/event_handlers/"+strconv.FormatInt(h.ID, 10), h.payload(h.ID))
}

// Delete deletes the event handler. If h.ID is zero the handler is looked up
// by name and type first; [ErrNotFound] is returned if it does not exist.
func (s *EventHandlerService) Delete(ctx context.Context, h *EventHandler) (json.RawMessage, error) {
	id := h.ID
	if id == 0 {
		found, err := s.GetByName(ctx, h.Name, h.Type)
		if err != nil {
			return nil, err
		}
		if found.ID == 0 {
			return nil, fmt.Errorf("mamori: event handler %q: %w", h.Name, ErrNotFound)
		}
		id = found.ID
	}
	return s.DeleteByID(ctx, id)
}

// DeleteByID deletes the event handler with the given id.
func (s *EventHandlerService) DeleteByID(ctx context.Context, id int64) (json.RawMessage, error) {
	return s.client.Call(ctx, http.MethodDelete, "/v1/event_handlers/"+strconv.FormatInt(id, 10), nil)
}

// Test runs the handler with a JSON payload (trigger, rule and policy_data
// handlers only). h.Body, when set, is sent so unsaved content can be tested.
func (s *EventHandlerService) Test(ctx context.Context, h *EventHandler, payload any) (json.RawMessage, error) {
	rec := Params{
		"type":    h.Type,
		"name":    h.Name,
		"payload": payload,
	}
	if h.Body != "" {
		rec["body"] = h.Body
	}
	if h.Capabilities != nil {
		rec["capabilities"] = h.Capabilities
	}
	return s.client.Call(ctx, http.MethodPost, "/v1/event_handlers/test", rec)
}
