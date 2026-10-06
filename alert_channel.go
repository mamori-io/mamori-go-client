package mamori

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// AlertChannelPolicyType is the policy type of an alert channel.
type AlertChannelPolicyType string

// Alert channel policy types.
const (
	AlertChannelPolicyTypePolicy AlertChannelPolicyType = "policy"
	AlertChannelPolicyTypeOther  AlertChannelPolicyType = "other"
)

// AlertType is the kind of an alert channel action.
type AlertType string

// Alert action types.
const (
	AlertTypeEmail        AlertType = "email"
	AlertTypeHTTP         AlertType = "http"
	AlertTypeNotification AlertType = "notification"
)

// HTTPOperation is the HTTP method used by an HTTP alert action.
type HTTPOperation string

// HTTP alert operations.
const (
	HTTPOperationGet    HTTPOperation = "GET"
	HTTPOperationPost   HTTPOperation = "POST"
	HTTPOperationPut    HTTPOperation = "PUT"
	HTTPOperationDelete HTTPOperation = "DELETE"
)

// NotificationType is the kind of notification sent by a notification alert
// action.
type NotificationType string

// Notification types.
const (
	NotificationTypeMessage NotificationType = "Message"
	NotificationTypePush    NotificationType = "PushMessage"
)

// AlertChannelAction is a single action of an alert channel. Only the params
// slice matching Name is used when the channel is saved.
type AlertChannelAction struct {
	// Name is the action type (see [AlertType]); actions read from the
	// server have upper-case names.
	Name string `json:"name"`
	// Key is a sequence number assigned when the channel is read.
	Key int `json:"key"`
	// EmailParams are recipients, subject and message.
	EmailParams []string `json:"email_params"`
	// HTTPParams are method, URL, base64 body, content type and headers.
	HTTPParams []string `json:"http_params"`
	// NotificationParams are recipient, notification type and message.
	NotificationParams []string `json:"notification_params"`
}

// Params returns the parameters belonging to the action's type.
func (a AlertChannelAction) Params() []string {
	switch AlertType(strings.ToLower(a.Name)) {
	case AlertTypeEmail:
		return a.EmailParams
	case AlertTypeHTTP:
		return a.HTTPParams
	case AlertTypeNotification:
		return a.NotificationParams
	}
	return nil
}

// Describe returns a human readable description of the action.
func (a AlertChannelAction) Describe() string {
	p := a.Params()
	at := func(i int) string {
		if i < len(p) {
			return p[i]
		}
		return ""
	}
	switch AlertType(strings.ToLower(a.Name)) {
	case AlertTypeEmail:
		return "Send email to " + at(0) + " with subject '" + at(1) + "'"
	case AlertTypeHTTP:
		u, err := url.Parse(at(1))
		if err != nil {
			return "Perform " + at(0) + " request to " + at(1)
		}
		path := u.EscapedPath()
		if path == "" {
			path = "/"
		}
		return "Perform " + u.Scheme + " " + at(0) + " request to " + u.Host + " at " + path
	case AlertTypeNotification:
		return "Send a notification to " + at(0)
	}
	return "UNKNOWN ACTION " + a.Name
}

// AlertChannel is a named sequence of alert actions (email, HTTP call,
// notification).
type AlertChannel struct {
	ID      int64                `json:"id,omitempty"`
	Name    string               `json:"name"`
	Actions []AlertChannelAction `json:"actions"`
	// Description is a summary of the actions, filled in when read from the
	// server.
	Description string `json:"description,omitempty"`
}

// NewAlertChannel returns an empty alert channel.
func NewAlertChannel(name string) *AlertChannel {
	return &AlertChannel{Name: name, Actions: []AlertChannelAction{}}
}

// AddEmailAlert appends an email action. emails is a comma separated list of
// recipients.
func (a *AlertChannel) AddEmailAlert(emails, subject, message string) []AlertChannelAction {
	a.Actions = append(a.Actions, AlertChannelAction{
		Name:        string(AlertTypeEmail),
		EmailParams: []string{emails, subject, message},
	})
	return a.Actions
}

// AddHTTPAlert appends an HTTP request action. body is base64 encoded.
func (a *AlertChannel) AddHTTPAlert(op HTTPOperation, header, url, body, contentType string) []AlertChannelAction {
	a.Actions = append(a.Actions, AlertChannelAction{
		Name:       string(AlertTypeHTTP),
		HTTPParams: []string{string(op), url, Base64Encode(body), contentType, header},
	})
	return a.Actions
}

// AddPushNotificationAlert appends a push notification action.
func (a *AlertChannel) AddPushNotificationAlert(recipient, message string) []AlertChannelAction {
	a.Actions = append(a.Actions, AlertChannelAction{
		Name:               string(AlertTypeNotification),
		NotificationParams: []string{recipient, string(NotificationTypePush), message},
	})
	return a.Actions
}

// AddMessageAlert appends an in-app message notification action.
func (a *AlertChannel) AddMessageAlert(recipient, message string) []AlertChannelAction {
	a.Actions = append(a.Actions, AlertChannelAction{
		Name:               string(AlertTypeNotification),
		NotificationParams: []string{recipient, string(NotificationTypeMessage), message},
	})
	return a.Actions
}

// EncodeActions returns the actions in the server's s-expression form, e.g.
// `(email "a@b.com" "subject" "body")`.
func (a *AlertChannel) EncodeActions() (string, error) {
	var sb strings.Builder
	for _, act := range a.Actions {
		sb.WriteString("(")
		sb.WriteString(act.Name)
		sb.WriteString(" ")
		for i, p := range act.Params() {
			if i > 0 {
				sb.WriteString(" ")
			}
			var buf bytes.Buffer
			enc := json.NewEncoder(&buf)
			enc.SetEscapeHTML(false)
			if err := enc.Encode(p); err != nil {
				return "", err
			}
			sb.Write(bytes.TrimRight(buf.Bytes(), "\n"))
		}
		sb.WriteString(")")
	}
	return sb.String(), nil
}

func (a *AlertChannel) payload() (Params, error) {
	action, err := a.EncodeActions()
	if err != nil {
		return nil, err
	}
	return Params{"alert": Params{"name": a.Name, "action": action}}, nil
}

var alertChannelUnescaper = strings.NewReplacer(`\n`, "\n", `\t`, "\t", `\"`, `"`)

// alertChannelProcess converts a server alert record into an AlertChannel.
func alertChannelProcess(rec alertChannelRecord) (AlertChannel, error) {
	ch := AlertChannel{ID: rec.ID, Name: rec.Name, Actions: []AlertChannelAction{}}
	items, err := ParseSexp("(" + rec.Action + ")")
	if err != nil {
		return ch, fmt.Errorf("mamori: alert channel %q: %w", rec.Name, err)
	}
	descs := make([]string, 0, len(items))
	for key, it := range items {
		list, ok := it.([]any)
		if !ok || len(list) == 0 {
			continue
		}
		n := alertChannelAtom(list[0])
		params := make([]string, 0, len(list)-1)
		for _, p := range list[1:] {
			params = append(params, alertChannelUnescaper.Replace(alertChannelAtom(p)))
		}
		act := AlertChannelAction{
			Name:               strings.ToUpper(n),
			Key:                key,
			EmailParams:        []string{},
			HTTPParams:         []string{},
			NotificationParams: []string{},
		}
		switch AlertType(strings.ToLower(n)) {
		case AlertTypeEmail:
			act.EmailParams = params
		case AlertTypeHTTP:
			act.HTTPParams = params
		case AlertTypeNotification:
			act.NotificationParams = params
		}
		ch.Actions = append(ch.Actions, act)
		descs = append(descs, act.Describe())
	}
	ch.Description = strings.Join(descs, " then ")
	return ch, nil
}

func alertChannelAtom(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case Symbol:
		return string(t)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	}
	return fmt.Sprint(v)
}

type alertChannelRecord struct {
	ID     int64  `json:"id"`
	Name   string `json:"name"`
	Action string `json:"action"`
}

// List returns all alert channels, with their actions decoded.
func (s *AlertChannelService) List(ctx context.Context) ([]AlertChannel, error) {
	var recs []alertChannelRecord
	if err := s.client.CallInto(ctx, http.MethodGet, "/v1/alerts", nil, &recs); err != nil {
		return nil, err
	}
	out := make([]AlertChannel, 0, len(recs))
	for _, r := range recs {
		ch, err := alertChannelProcess(r)
		if err != nil {
			return nil, err
		}
		out = append(out, ch)
	}
	return out, nil
}

// Get returns the alert channel with the given name, or [ErrNotFound].
func (s *AlertChannelService) Get(ctx context.Context, name string) (*AlertChannel, error) {
	list, err := s.List(ctx)
	if err != nil {
		return nil, err
	}
	for i := range list {
		if list[i].Name == name {
			return &list[i], nil
		}
	}
	return nil, fmt.Errorf("mamori: alert channel %q: %w", name, ErrNotFound)
}

// Create creates the alert channel. If the response carries the new id it is
// stored in a.ID.
func (s *AlertChannelService) Create(ctx context.Context, a *AlertChannel) (json.RawMessage, error) {
	p, err := a.payload()
	if err != nil {
		return nil, err
	}
	raw, err := s.client.Call(ctx, http.MethodPost, "/v1/alerts", p)
	if err != nil {
		return nil, err
	}
	var res struct {
		ID int64 `json:"id"`
	}
	if json.Unmarshal(raw, &res) == nil && res.ID != 0 {
		a.ID = res.ID
	}
	return raw, nil
}

// Update saves the name and actions of the alert channel a.ID.
func (s *AlertChannelService) Update(ctx context.Context, a *AlertChannel) (json.RawMessage, error) {
	p, err := a.payload()
	if err != nil {
		return nil, err
	}
	return s.client.Call(ctx, http.MethodPut, "/v1/alerts/"+strconv.FormatInt(a.ID, 10), p)
}

// Delete deletes the alert channel with the given id.
func (s *AlertChannelService) Delete(ctx context.Context, id int64) (json.RawMessage, error) {
	return s.client.Call(ctx, http.MethodDelete, "/v1/alerts/"+strconv.FormatInt(id, 10), nil)
}
