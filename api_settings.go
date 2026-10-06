package mamori

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
)

// DriverSpec describes a JDBC driver to register (TS DriverRec).
type DriverSpec struct {
	Name                   string `json:"name"`
	Type                   string `json:"type"`
	Classname              string `json:"classname"`
	IncludeParentClasspath bool   `json:"include_parent_classpath"`
	ResourceFiles          []any  `json:"resource_files"`
}

//
// Database policies
//

// CreateDBPolicy creates a database policy. priority is only sent when it is
// set and numeric (a non-zero number or a numeric string), as in the TS SDK.
func (c *Client) CreateDBPolicy(ctx context.Context, name string, priority any, description string) (json.RawMessage, error) {
	p := Params{"name": name, "description": description}
	if settingsNumericPriority(priority) {
		p["priority"] = priority
	}
	return c.Call(ctx, http.MethodPost, "/v1/policies/dbpolicy", p)
}

// settingsNumericPriority mirrors the JS truthy-and-numeric check applied to
// a policy priority.
func settingsNumericPriority(v any) bool {
	switch t := v.(type) {
	case int:
		return t != 0
	case int32:
		return t != 0
	case int64:
		return t != 0
	case float32:
		return t != 0
	case float64:
		return t != 0
	case json.Number:
		f, err := t.Float64()
		return err == nil && f != 0
	case string:
		if t == "" {
			return false
		}
		_, err := strconv.ParseFloat(t, 64)
		return err == nil
	default:
		return false
	}
}

// ReadDBPolicy returns the named database policy.
func (c *Client) ReadDBPolicy(ctx context.Context, name string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/policies/dbpolicy/"+name, nil)
}

// DeleteDBPolicy deletes the named database policy.
func (c *Client) DeleteDBPolicy(ctx context.Context, name string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodDelete, "/v1/policies/dbpolicy/"+name, nil)
}

// UpdateDBPolicy updates the database policy identified by id (a name or a
// numeric id) with rec.
func (c *Client) UpdateDBPolicy(ctx context.Context, id any, rec any) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPut, "/v1/policies/dbpolicy/"+fmt.Sprint(id), rec)
}

//
// SMTP
//

// GetSMTPConfig returns the SMTP configuration, augmented with "logo" and
// "logo_height" taken from the email_logo and email_logo_height system
// properties.
func (c *Client) GetSMTPConfig(ctx context.Context) (Params, error) {
	var data Params
	if err := c.CallInto(ctx, http.MethodGet, "/v1/smtp", nil, &data); err != nil {
		return nil, err
	}
	var props Params
	if err := c.CallInto(ctx, http.MethodGet, "/v1/server_properties", nil, &props); err != nil {
		return nil, err
	}
	if data == nil {
		data = Params{}
	}
	data["logo"] = props["email_logo"]
	data["logo_height"] = props["email_logo_height"]
	return data, nil
}

// SetSMTPConfig saves the SMTP configuration and then stores options["logo"]
// and options["logo_height"] in the email_logo and email_logo_height system
// properties. The result of the second call is returned.
func (c *Client) SetSMTPConfig(ctx context.Context, options Params) (json.RawMessage, error) {
	if _, err := c.Call(ctx, http.MethodPut, "/v1/smtp", options); err != nil {
		return nil, err
	}
	return c.SetSystemProperties(ctx, Params{
		"email_logo":        options["logo"],
		"email_logo_height": options["logo_height"],
	})
}

// SendTestEmail sends a test email using the supplied SMTP options.
func (c *Client) SendTestEmail(ctx context.Context, options any) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPost, "/v1/smtp/test", options)
}

//
// System properties
//

// SystemProperties returns all server properties.
func (c *Client) SystemProperties(ctx context.Context) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/server_properties", nil)
}

// GetSystemProperties returns server properties. query is appended verbatim
// to "/v1/server_properties", so it should carry its own leading "?".
func (c *Client) GetSystemProperties(ctx context.Context, query string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/server_properties"+query, nil)
}

// SetSystemProperties updates several server properties at once.
func (c *Client) SetSystemProperties(ctx context.Context, properties any) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPut, "/v1/server_properties", Params{"properties": properties})
}

// SetSystemProperty sets a single server property.
func (c *Client) SetSystemProperty(ctx context.Context, name string, value any) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPut, "/v1/server_properties/"+name, Params{"value": value})
}

//
// Activity monitoring
//

// ConnectionInfo returns the connection log entry for a session. When
// sshStreams is true the SSH streams are included.
func (c *Client) ConnectionInfo(ctx context.Context, ssid string, sshStreams bool) (json.RawMessage, error) {
	path := "/v1/connection_log/" + pathEscape(ssid)
	if sshStreams {
		path += "?ssh_streams=y"
	}
	return c.Call(ctx, http.MethodGet, path, nil)
}

// SearchConnectionLog searches the connection log.
func (c *Client) SearchConnectionLog(ctx context.Context, options any) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPut, "/v1/search/connection_log", options)
}

// SearchConnectionEvents searches connection events.
func (c *Client) SearchConnectionEvents(ctx context.Context, options any) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPut, "/v1/search/connection_events", options)
}

// SSHSessionLog returns the SSH session log for a session. options (may be
// nil) are sent as query parameters.
func (c *Client) SSHSessionLog(ctx context.Context, ssid string, options any) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/ssh/"+pathEscape(ssid), options)
}

// SSHVideoOptions returns the SSH session video options.
func (c *Client) SSHVideoOptions(ctx context.Context) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/ssh/video/options", nil)
}

//
// Drivers
//

// DriversResources lists the resource files of a driver.
func (c *Client) DriversResources(ctx context.Context, driverName string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/drivers/"+driverName+"/files", nil)
}

// DriversForType lists the drivers of the given type.
func (c *Client) DriversForType(ctx context.Context, driverType string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/drivers?type="+pathEscape(driverType), nil)
}

// CreateDriverForSpec registers the driver described by spec.
func (c *Client) CreateDriverForSpec(ctx context.Context, spec DriverSpec) (json.RawMessage, error) {
	return c.CreateDriver(ctx, spec.Name, spec.Type, spec.Classname, spec.IncludeParentClasspath, spec.ResourceFiles)
}

// CreateDriver registers a driver.
func (c *Client) CreateDriver(ctx context.Context, driverName, driverType, classname string, includeParentClasspath bool, resourceFiles []any) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPost, "/v1/drivers", Params{
		"name":                     driverName,
		"type":                     driverType,
		"classname":                classname,
		"include_parent_classpath": includeParentClasspath,
		"resource_files":           resourceFiles,
	})
}

// UpdateDriver updates a driver.
func (c *Client) UpdateDriver(ctx context.Context, driverName string, options any) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPut, "/v1/drivers/"+driverName, options)
}

// DeleteDriver deletes a driver.
func (c *Client) DeleteDriver(ctx context.Context, driverName string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodDelete, "/v1/drivers/"+driverName, nil)
}
