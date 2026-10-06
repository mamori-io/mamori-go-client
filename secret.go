package mamori

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strconv"
)

// SecretProtocol is the protocol a secret is used for.
type SecretProtocol string

// Secret protocols.
const (
	SecretProtocolGeneric SecretProtocol = ""
	SecretProtocolRDP     SecretProtocol = "rdp"
	SecretProtocolSSH     SecretProtocol = "ssh"
	SecretProtocolDB      SecretProtocol = "db"
)

// SecretType distinguishes plain secrets from multi-part secrets.
type SecretType string

// Secret types.
const (
	SecretTypeSecret      SecretType = "SECRET"
	SecretTypeMultiSecret SecretType = "MULTI-SECRET"
)

// Secret is a stored secret.
//
// A plain secret carries its value in Secret. A multi-part secret
// (SecretTypeMultiSecret) is made of other secrets: list their names in
// Parts. When Parts is non-nil the secret is sent to the server as a
// multi-part secret (its parts JSON encoded) and Secret is ignored; this
// mirrors the TypeScript SDK, where a non-string `secret` value makes a
// MULTI-SECRET. [SecretService.GetByName] fills Parts for multi-part secrets.
type Secret struct {
	ID       string         `json:"id"`
	Type     SecretType     `json:"type"`
	Protocol SecretProtocol `json:"protocol"`
	Secret   string         `json:"secret"`
	// Parts are the names of the secrets making up a multi-part secret.
	Parts        []string `json:"-"`
	Name         string   `json:"name"`
	Username     string   `json:"username"`
	Hostname     string   `json:"hostname"`
	Description  string   `json:"description"`
	UpdatedAt    string   `json:"updated_at"`
	CreatedAt    string   `json:"created_at"`
	ActiveAccess string   `json:"active_access"`
	Encoding     string   `json:"encoding"`
	ExpiresAt    string   `json:"expires_at,omitempty"`
	AlertAt      string   `json:"alert_at,omitempty"`
	ExpiryAlert  string   `json:"expiry_alert"`
}

// NewSecret returns a plain text secret with the TypeScript SDK defaults.
func NewSecret(protocol SecretProtocol, name string) *Secret {
	return &Secret{Protocol: protocol, Type: SecretTypeSecret, Name: name, Encoding: "text"}
}

// UnmarshalJSON decodes a secret record, tolerating numeric ids.
func (s *Secret) UnmarshalJSON(b []byte) error {
	return looseUnmarshal(b, s)
}

// secretParams returns the create/update payload for s (TS toParams): every
// field except id and type, with type derived from whether s is multi-part.
func secretParams(s *Secret) (Params, error) {
	p := Params{
		"protocol":      s.Protocol,
		"name":          s.Name,
		"username":      s.Username,
		"hostname":      s.Hostname,
		"description":   s.Description,
		"updated_at":    s.UpdatedAt,
		"created_at":    s.CreatedAt,
		"active_access": s.ActiveAccess,
		"encoding":      s.Encoding,
		"expiry_alert":  s.ExpiryAlert,
	}
	if s.ExpiresAt != "" {
		p["expires_at"] = s.ExpiresAt
	}
	if s.AlertAt != "" {
		p["alert_at"] = s.AlertAt
	}
	if s.Parts != nil {
		b, err := json.Marshal(s.Parts)
		if err != nil {
			return nil, err
		}
		p["secret"] = string(b)
		p["type"] = SecretTypeMultiSecret
	} else {
		p["secret"] = s.Secret
		p["type"] = SecretTypeSecret
	}
	return p, nil
}

// RevealWithID reveals a secret by id using the REVEAL_SECRET procedure and
// returns the first result row.
func (s *SecretService) RevealWithID(ctx context.Context, id string) (Row, error) {
	if err := checkSQLNumber(id); err != nil {
		return nil, err
	}
	return firstRow(s.client.Select(ctx, "call REVEAL_SECRET("+id+")"))
}

// List searches secrets. Non-admins only see secrets granted to them.
func (s *SecretService) List(ctx context.Context, opts SearchOptions) (*SearchResult[Secret], error) {
	var res SearchResult[Secret]
	if err := s.client.CallInto(ctx, http.MethodPut, "/v1/search/secrets", opts.params(), &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// findByName returns the first secret named name, or ErrNotFound.
func (s *SecretService) findByName(ctx context.Context, name string) (*Secret, error) {
	res, err := s.List(ctx, SearchOptions{Skip: 0, Take: 100, Filter: Filters{F("name", FilterEquals, name)}})
	if err != nil {
		return nil, err
	}
	if len(res.Data) == 0 {
		return nil, fmt.Errorf("mamori: secret %q: %w", name, ErrNotFound)
	}
	return &res.Data[0], nil
}

// GetByName returns the secret named name, or ErrNotFound. For multi-part
// secrets Parts is filled in.
func (s *SecretService) GetByName(ctx context.Context, name string) (*Secret, error) {
	sec, err := s.findByName(ctx, name)
	if err != nil {
		return nil, err
	}
	if sec.Type == SecretTypeMultiSecret {
		parts, err := s.GetMultiSecretParts(ctx, sec.ID)
		if err != nil {
			return nil, err
		}
		sec.Parts = parts
	}
	return sec, nil
}

// ExportByName returns the secret named name with its value exported
// (encrypted) with the encryption key keyName, ready for
// [SecretService.RestoreWithKey]. It returns ErrNotFound if there is no such
// secret.
func (s *SecretService) ExportByName(ctx context.Context, name, keyName string) (*Secret, error) {
	sec, err := s.findByName(ctx, name)
	if err != nil {
		return nil, err
	}
	val, err := s.ExportSecret(ctx, sec.Name, keyName)
	if err != nil {
		return nil, err
	}
	sec.Secret, sec.Parts = "", nil
	if val != nil {
		var str string
		if json.Unmarshal(val, &str) == nil {
			sec.Secret = str
		} else if err := json.Unmarshal(val, &sec.Parts); err != nil {
			return nil, fmt.Errorf("mamori: unexpected exported secret value %s", val)
		}
	}
	return sec, nil
}

// DeleteByName deletes the secret named name and returns it, or returns
// ErrNotFound if there is no such secret.
func (s *SecretService) DeleteByName(ctx context.Context, name string) (*Secret, error) {
	sec, err := s.GetByName(ctx, name)
	if err != nil {
		return nil, err
	}
	if _, err := s.Delete(ctx, sec.ID); err != nil {
		return nil, err
	}
	return sec, nil
}

// Create creates sec and returns the first element of the response.
func (s *SecretService) Create(ctx context.Context, sec *Secret) (json.RawMessage, error) {
	p, err := secretParams(sec)
	if err != nil {
		return nil, err
	}
	return firstElement(s.client.Call(ctx, http.MethodPost, "/v1/secrets/", Params{"secret": p}))
}

// Restore restores a previously exported, unencrypted secret.
func (s *SecretService) Restore(ctx context.Context, sec *Secret) (json.RawMessage, error) {
	return s.RestoreWithKey(ctx, sec, "")
}

// RestoreWithKey restores a secret exported with the encryption key
// keyName. An empty keyName is the same as [SecretService.Restore].
func (s *SecretService) RestoreWithKey(ctx context.Context, sec *Secret, keyName string) (json.RawMessage, error) {
	p, err := secretParams(sec)
	if err != nil {
		return nil, err
	}
	body := Params{"restore": true, "secret": p}
	if keyName != "" {
		body["key"] = keyName
	}
	return firstElement(s.client.Call(ctx, http.MethodPost, "/v1/secrets/", body))
}

// Delete deletes the secret with the given id.
func (s *SecretService) Delete(ctx context.Context, id string) (json.RawMessage, error) {
	return s.client.Call(ctx, http.MethodDelete, "/v1/secrets/"+pathEscape(id), nil)
}

// Update updates the secret identified by sec.ID and returns the first
// element of the response.
func (s *SecretService) Update(ctx context.Context, sec *Secret) (json.RawMessage, error) {
	if sec.ID == "" {
		return nil, fmt.Errorf("mamori: secret %q has no id", sec.Name)
	}
	p, err := secretParams(sec)
	if err != nil {
		return nil, err
	}
	return firstElement(s.client.Call(ctx, http.MethodPut, "/v1/secrets/"+pathEscape(sec.ID), Params{"secret": p}))
}

// Reveal returns the secret with the given id including its value.
func (s *SecretService) Reveal(ctx context.Context, id string) (json.RawMessage, error) {
	return s.client.Call(ctx, http.MethodGet, "/v1/secrets/"+pathEscape(id)+"/reveal", nil)
}

// ExportSecret exports the named secret, encrypted with the encryption key
// keyName when it is non-empty, and returns the exported value (nil if the
// server returned none).
func (s *SecretService) ExportSecret(ctx context.Context, name, keyName string) (json.RawMessage, error) {
	var params Params
	if keyName != "" {
		params = Params{"key": keyName}
	}
	var rows []struct {
		Value json.RawMessage `json:"value"`
	}
	if err := s.client.CallInto(ctx, http.MethodGet, "/v1/secrets/"+pathEscape(name)+"/export", params, &rows); err != nil {
		return nil, err
	}
	if len(rows) == 0 || len(rows[0].Value) == 0 || string(rows[0].Value) == "null" {
		return nil, nil
	}
	return rows[0].Value, nil
}

// GetMultiSecretParts returns the names of the secrets making up the
// multi-part secret with the given id.
func (s *SecretService) GetMultiSecretParts(ctx context.Context, id string) ([]string, error) {
	var res struct {
		Parts string `json:"parts"`
	}
	if err := s.client.CallInto(ctx, http.MethodGet, "/v1/secrets/"+pathEscape(id)+"/parts", nil, &res); err != nil {
		return nil, err
	}
	parts := []string{}
	if res.Parts == "" {
		return parts, nil
	}
	if err := json.Unmarshal([]byte(res.Parts), &parts); err != nil {
		return nil, fmt.Errorf("mamori: decoding secret parts: %w", err)
	}
	return parts, nil
}

// GrantTo grants access to the named secret to grantee.
func (s *SecretService) GrantTo(ctx context.Context, name, grantee string) error {
	_, err := s.client.Permissions.Grant(ctx, NewSecretPermission(name, grantee))
	return err
}

// RevokeFrom revokes access to the named secret from grantee.
func (s *SecretService) RevokeFrom(ctx context.Context, name, grantee string) error {
	_, err := s.client.Permissions.Revoke(ctx, NewSecretPermission(name, grantee))
	return err
}

// looseUnmarshal decodes a JSON object into the struct pointed to by out,
// matching keys to json tags and coercing scalar types the way the
// TypeScript SDK's untyped records allow (numeric ids into strings, numeric
// strings into ints, "true"/"false" into bools). Only keys present in the
// object are assigned, like the TypeScript fromJSON methods.
func looseUnmarshal(b []byte, out any) error {
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	looseAssign(m, out)
	return nil
}

// looseAssign assigns the values of m to the tagged fields of the struct
// pointed to by out; see looseUnmarshal.
func looseAssign(m map[string]any, out any) {
	rv := reflect.ValueOf(out).Elem()
	rt := rv.Type()
	for i := 0; i < rt.NumField(); i++ {
		sf := rt.Field(i)
		if !sf.IsExported() {
			continue
		}
		name := sf.Tag.Get("json")
		for j := 0; j < len(name); j++ {
			if name[j] == ',' {
				name = name[:j]
				break
			}
		}
		if name == "" || name == "-" {
			continue
		}
		v, ok := m[name]
		if !ok {
			continue
		}
		looseSet(rv.Field(i), v)
	}
}

func looseSet(f reflect.Value, v any) {
	switch f.Kind() {
	case reflect.String:
		switch x := v.(type) {
		case nil:
			f.SetString("")
		case string:
			f.SetString(x)
		case float64:
			f.SetString(strconv.FormatFloat(x, 'f', -1, 64))
		case bool:
			f.SetString(strconv.FormatBool(x))
		default:
			b, _ := json.Marshal(x)
			f.SetString(string(b))
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		switch x := v.(type) {
		case float64:
			f.SetInt(int64(x))
		case string:
			if n, err := strconv.ParseInt(x, 10, 64); err == nil {
				f.SetInt(n)
			}
		}
	case reflect.Bool:
		switch x := v.(type) {
		case bool:
			f.SetBool(x)
		case float64:
			f.SetBool(x != 0)
		case string:
			if b, err := strconv.ParseBool(x); err == nil {
				f.SetBool(b)
			}
		case nil:
			f.SetBool(false)
		}
	case reflect.Interface:
		if v == nil {
			f.SetZero()
		} else {
			f.Set(reflect.ValueOf(v))
		}
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return
		}
		nv := reflect.New(f.Type())
		if json.Unmarshal(b, nv.Interface()) == nil {
			f.Set(nv.Elem())
		}
	}
}
