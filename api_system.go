package mamori

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
)

//
// Database objects
//

// Objects lists database objects of a system. name optionally restricts the
// result to a single object ("" for all).
func (c *Client) Objects(ctx context.Context, systemName, databaseName, schemaName, name string) (json.RawMessage, error) {
	p := Params{
		"system_name":   systemName,
		"database_name": databaseName,
		"schema_name":   schemaName,
	}
	if name != "" {
		p["object_name"] = name
	}
	return c.Call(ctx, http.MethodGet, "/v1/objects", p)
}

//
// System groups
//

// SystemGroupsSearch searches system groups.
func (c *Client) SystemGroupsSearch(ctx context.Context, options any) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPut, "/v1/systemgroups", options)
}

// CreateSystemGroup creates a system group.
func (c *Client) CreateSystemGroup(ctx context.Context, options any) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPost, "/v1/systemgroups", options)
}

// DeleteSystemGroup deletes a system group.
func (c *Client) DeleteSystemGroup(ctx context.Context, name string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodDelete, "/v1/systemgroups/"+name, nil)
}

// AlterSystemGroup updates a system group.
func (c *Client) AlterSystemGroup(ctx context.Context, name string, options any) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPut, "/v1/systemgroups/"+name, options)
}

// SystemGroupSystemsSearch searches the systems in a system group.
func (c *Client) SystemGroupSystemsSearch(ctx context.Context, group string, options any) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPut, "/v1/systemgroups/"+group+"/systems", options)
}

// SystemGroupAddSystem adds a system to a system group.
func (c *Client) SystemGroupAddSystem(ctx context.Context, group, system string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPost, "/v1/systemgroups/"+group+"/systems", Params{"system": system})
}

// SystemGroupRemoveSystem removes a system from a system group.
func (c *Client) SystemGroupRemoveSystem(ctx context.Context, group, system string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodDelete, "/v1/systemgroups/"+group+"/systems/"+system, nil)
}

// SystemGroupAddCredential adds a database credential for grantee to every
// system in a system group.
func (c *Client) SystemGroupAddCredential(ctx context.Context, group, grantee, login, pw string, options any) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPost, "/v1/systemgroups/"+group+"/credentials", Params{
		"grantee": grantee,
		"login":   login,
		"pw":      pw,
		"options": options,
	})
}

// SystemGroupRemoveCredential removes a credential from a system group.
func (c *Client) SystemGroupRemoveCredential(ctx context.Context, group string, options any) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPost, "/v1/systemgroups/"+group+"/credentials/delete", options)
}

// SystemGroupCredentialsSearch searches the credentials of a system group.
func (c *Client) SystemGroupCredentialsSearch(ctx context.Context, group string, options any) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPut, "/v1/systemgroups/"+group+"/credentials", options)
}

//
// Miscellaneous server information
//

// GetQRCode checks the status of an MFA QR code by id.
func (c *Client) GetQRCode(ctx context.Context, id string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/ua/qrcheck/"+pathEscape(id), nil)
}

// CreateBackup creates a server configuration backup.
func (c *Client) CreateBackup(ctx context.Context) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/backup", nil)
}

// ServerTime returns the server's current time.
func (c *Client) ServerTime(ctx context.Context) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/time", nil)
}

// ServerVersion returns the server version information.
func (c *Client) ServerVersion(ctx context.Context) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/version", nil)
}

// GetTimezones returns the time zones known to the server.
func (c *Client) GetTimezones(ctx context.Context) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/timezones", nil)
}

//
// Certificates and logs
//

// Certs returns the installed server certificates.
func (c *Client) Certs(ctx context.Context) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/certs", nil)
}

// InstallCerts installs a named set of certificates (PEM encoded CA
// certificate, private key and certificate).
func (c *Client) InstallCerts(ctx context.Context, name, caCrt, key, crt string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPost, "/v1/certs", Params{
		"name":  name,
		"certs": Params{"key": key, "crt": crt, "ca_crt": caCrt},
	})
}

// GetLogEntries returns the entries of a named system log.
func (c *Client) GetLogEntries(ctx context.Context, logname string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/logs/system/"+logname, nil)
}

// GetLogsZipfile downloads the server logs as a zip archive.
func (c *Client) GetLogsZipfile(ctx context.Context) ([]byte, error) {
	return c.CallBinary(ctx, http.MethodGet, "/v1/logs/download", nil)
}

//
// Alerts
//

// Alerts lists the configured alerts.
func (c *Client) Alerts(ctx context.Context) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/alerts", nil)
}

// GetAlert returns an alert by id.
func (c *Client) GetAlert(ctx context.Context, id int64) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/alerts/"+strconv.FormatInt(id, 10), nil)
}

// CreateAlert creates an alert.
func (c *Client) CreateAlert(ctx context.Context, alert any) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPost, "/v1/alerts", Params{"alert": alert})
}

// UpdateAlert updates an alert.
func (c *Client) UpdateAlert(ctx context.Context, id int64, alert any) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPut, "/v1/alerts/"+strconv.FormatInt(id, 10), Params{"alert": alert})
}

// DeleteAlert deletes an alert.
func (c *Client) DeleteAlert(ctx context.Context, id int64) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodDelete, "/v1/alerts/"+strconv.FormatInt(id, 10), nil)
}

//
// Listeners
//

// Listeners lists the server's protocol listeners.
func (c *Client) Listeners(ctx context.Context) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/listeners", nil)
}

// GetDetailedLoggingForListener returns the detailed logging setting of a
// listener.
func (c *Client) GetDetailedLoggingForListener(ctx context.Context, listener string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/listeners/"+listener+"/logging", nil)
}

// UpdateListener changes the port of a listener.
func (c *Client) UpdateListener(ctx context.Context, id string, port int) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPut, "/v1/listeners/"+id, Params{"port": port})
}

// UpdateListenerLogging enables or disables detailed logging for a listener.
func (c *Client) UpdateListenerLogging(ctx context.Context, id string, flag bool) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPut, "/v1/listeners/"+id+"/logging", Params{"detailed_logging": flag})
}

//
// Server domain
//

// SetServerDomain points the server's externally visible URLs at domain: the
// SMTP web URL, the WireGuard public address, the RDP URI and the service URL
// of the pushtotp and pushmobile providers. All updates are attempted; the
// returned error joins any failures.
func (c *Client) SetServerDomain(ctx context.Context, domain string) error {
	if _, err := c.GetSMTPConfig(ctx); err != nil {
		return err
	}
	url := "https://" + domain + "/"
	var errs []error
	add := func(_ json.RawMessage, err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}
	add(c.SetSMTPConfig(ctx, Params{"web_url": url, "port": "", "server": "", "host": "", "ssl": false}))
	add(c.SetSystemProperties(ctx, Params{"wireguard_public_address": domain}))
	add(c.SetSystemProperties(ctx, Params{"rdp_uri": url + "rdp"}))
	for _, name := range []string{"pushtotp", "pushmobile"} {
		add(c.UpdateProvider(ctx, name, Params{
			"type":                         name,
			"name":                         name,
			"authentication_timeout":       "180",
			"cache_authentication_timeout": "900",
			"mamori_service_url":           url,
		}))
	}
	return errors.Join(errs...)
}
