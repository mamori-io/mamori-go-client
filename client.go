// Package mamori is a Go client for the mamori.io enterprise server.
//
// It is a port of the TypeScript mamori-ent-js-sdk. The [Client] type exposes
// the low-level REST API (the equivalent of MamoriService), returning
// [json.RawMessage] for endpoints with loosely-defined responses. Typed,
// higher-level resource helpers hang off the client as services, e.g.
// c.Secrets, c.Datasources and c.Permissions.
//
// A minimal session:
//
//	c, err := mamori.New("https://mamori.example.com", mamori.WithInsecureSkipVerify())
//	if err != nil { ... }
//	login, err := c.Login(ctx, "alice", "secret")
//	if err != nil { ... }
//	defer c.Logout(ctx)
//	rows, err := c.Select(ctx, "select * from SYS.USERS")
package mamori

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"sync"
)

// Version is the version of the upstream TypeScript SDK this package tracks.
const Version = "1.4.9"

// DefaultApplication is the application name sent on login.
const DefaultApplication = "Mamori API"

// Params is a convenience type for request parameters and loosely-typed
// request bodies.
type Params = map[string]any

// Row is a single result row returned by [Client.Select] and friends, keyed by
// column name.
type Row = map[string]any

// Client is a mamori server API client. It is safe for concurrent use once
// logged in. Create one with [New].
type Client struct {
	base       *url.URL
	httpClient *http.Client
	insecure   bool

	mu        sync.RWMutex
	csrf      string
	claims    Params
	rawClaims json.RawMessage
	username  string

	onAuthorization func(*Client)
	logger          *slog.Logger

	common service

	AlertChannels        *AlertChannelService
	ConnectionLogs       *ConnectionLogService
	Datasources          *DatasourceService
	DBCredentials        *DBCredentialService
	EventHandlers        *EventHandlerService
	HTTPResources        *HTTPResourceService
	IPResources          *IPResourceService
	Keys                 *KeyService
	Networks             *NetworkService
	OnDemandPolicies     *OnDemandPolicyService
	Permissions          *PermissionService
	Policies             *PolicyService
	Providers            *ProviderService
	RemoteDesktops       *RemoteDesktopService
	RequestableResources *RequestableResourceService
	Roles                *RoleService
	ScriptFlows          *ScriptFlowService
	Scripts              *ScriptService
	Secrets              *SecretService
	ServerSettings       *ServerSettingsService
	SQLMaskingPolicies   *SQLMaskingPolicyService
	SSHLogins            *SSHLoginService
	Users                *UserService
	WireguardPeers       *WireguardPeerService
}

// service is embedded by every resource service to give access to the client.
type service struct {
	client *Client
}

// Option configures a [Client].
type Option func(*Client)

// WithHTTPClient sets the underlying HTTP client. If the client has no cookie
// jar, one is installed; mamori sessions are cookie based.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) { c.httpClient = hc }
}

// WithInsecureSkipVerify disables TLS certificate verification, for servers
// using self-signed certificates. It replaces the transport of the HTTP
// client, so apply it after [WithHTTPClient] if both are used.
func WithInsecureSkipVerify() Option {
	return func(c *Client) { c.insecure = true }
}

// WithAuthorizationHook registers a function called whenever the client's
// authorization changes (login or logout).
func WithAuthorizationHook(fn func(*Client)) Option {
	return func(c *Client) { c.onAuthorization = fn }
}

// New returns a client for the mamori server at baseURL, e.g.
// "https://mamori.example.com".
func New(baseURL string, opts ...Option) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("mamori: invalid base URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("mamori: base URL must be http or https, got %q", baseURL)
	}

	c := &Client{base: u}
	for _, opt := range opts {
		opt(c)
	}
	if c.httpClient == nil {
		c.httpClient = &http.Client{}
	} else {
		hc := *c.httpClient
		c.httpClient = &hc
	}
	if c.insecure {
		var tr *http.Transport
		if t, ok := c.httpClient.Transport.(*http.Transport); ok && t != nil {
			tr = t.Clone()
		} else {
			tr = http.DefaultTransport.(*http.Transport).Clone()
		}
		if tr.TLSClientConfig == nil {
			tr.TLSClientConfig = &tls.Config{}
		}
		tr.TLSClientConfig.InsecureSkipVerify = true
		c.httpClient.Transport = tr
	}
	if c.logger != nil {
		next := c.httpClient.Transport
		if next == nil {
			next = http.DefaultTransport
		}
		c.httpClient.Transport = &loggingTransport{next: next, log: c.logger}
	}
	if c.httpClient.Jar == nil {
		jar, err := cookiejar.New(nil)
		if err != nil {
			return nil, err
		}
		c.httpClient.Jar = jar
	}

	c.common.client = c
	c.AlertChannels = (*AlertChannelService)(&c.common)
	c.ConnectionLogs = (*ConnectionLogService)(&c.common)
	c.Datasources = (*DatasourceService)(&c.common)
	c.DBCredentials = (*DBCredentialService)(&c.common)
	c.EventHandlers = (*EventHandlerService)(&c.common)
	c.HTTPResources = (*HTTPResourceService)(&c.common)
	c.IPResources = (*IPResourceService)(&c.common)
	c.Keys = (*KeyService)(&c.common)
	c.Networks = (*NetworkService)(&c.common)
	c.OnDemandPolicies = (*OnDemandPolicyService)(&c.common)
	c.Permissions = (*PermissionService)(&c.common)
	c.Policies = (*PolicyService)(&c.common)
	c.Providers = (*ProviderService)(&c.common)
	c.RemoteDesktops = (*RemoteDesktopService)(&c.common)
	c.RequestableResources = (*RequestableResourceService)(&c.common)
	c.Roles = (*RoleService)(&c.common)
	c.ScriptFlows = (*ScriptFlowService)(&c.common)
	c.Scripts = (*ScriptService)(&c.common)
	c.Secrets = (*SecretService)(&c.common)
	c.ServerSettings = (*ServerSettingsService)(&c.common)
	c.SQLMaskingPolicies = (*SQLMaskingPolicyService)(&c.common)
	c.SSHLogins = (*SSHLoginService)(&c.common)
	c.Users = (*UserService)(&c.common)
	c.WireguardPeers = (*WireguardPeerService)(&c.common)
	return c, nil
}

// NewSession returns a new client for the same server and transport settings,
// but without the current session. Use it for a separate login (for example
// validating another user's password) without disturbing this client.
func (c *Client) NewSession() *Client {
	hc := *c.httpClient
	hc.Jar = nil
	nc, _ := New(c.base.String(), WithHTTPClient(&hc), WithAuthorizationHook(c.onAuthorization))
	return nc
}

// BaseURL returns the server base URL.
func (c *Client) BaseURL() string { return c.base.String() }

// HTTPClient returns the underlying HTTP client.
func (c *Client) HTTPClient() *http.Client { return c.httpClient }

// APIError is returned when the server responds with a non-2xx status.
type APIError struct {
	Method     string
	URL        string
	StatusCode int
	Status     string
	Body       []byte
}

func (e *APIError) Error() string {
	body := strings.TrimSpace(string(e.Body))
	if len(body) > 512 {
		body = body[:512] + "..."
	}
	if body == "" {
		return fmt.Sprintf("mamori: %s %s: %s", e.Method, e.URL, e.Status)
	}
	return fmt.Sprintf("mamori: %s %s: %s: %s", e.Method, e.URL, e.Status, body)
}

// StatusCode returns the HTTP status code of err if it is (or wraps) an
// [*APIError], otherwise 0.
func StatusCode(err error) int {
	if ae, ok := errors.AsType[*APIError](err); ok {
		return ae.StatusCode
	}
	return 0
}

// ErrNotLoggedIn is returned by operations that require an authenticated
// session.
var ErrNotLoggedIn = errors.New("mamori: not logged in")

// ErrNotFound is returned by lookup helpers when no matching object exists.
var ErrNotFound = errors.New("mamori: not found")

//
// Session state
//

// Claims returns the raw login response (the authorization claims) or nil if
// not logged in.
func (c *Client) Claims() Params {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.claims
}

// Authorized reports whether the client holds a session.
func (c *Client) Authorized() bool { return c.Claims() != nil }

// Username returns the name used to log in, or "" if not logged in.
func (c *Client) Username() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.username
}

// SessionID returns the server session id, or "" if not logged in or the
// server does not report one.
func (c *Client) SessionID() string {
	s, _ := c.Claims()["session_id"].(string)
	return s
}

// Restricted reports whether the session is restricted.
func (c *Client) Restricted() bool {
	b, _ := c.Claims()["restricted"].(bool)
	return b
}

// HasPriv reports whether the logged in user has the named privilege (or ALL
// PRIVILEGES).
func (c *Client) HasPriv(name string) bool {
	privs, _ := c.Claims()["privs"].([]any)
	for _, p := range privs {
		if s, _ := p.(string); s == name || s == "ALL PRIVILEGES" {
			return true
		}
	}
	return false
}

func (c *Client) setAuthorization(raw json.RawMessage, username string) error {
	var claims Params
	if raw != nil {
		if err := json.Unmarshal(raw, &claims); err != nil {
			return fmt.Errorf("mamori: decoding login response: %w", err)
		}
	}
	c.mu.Lock()
	c.rawClaims = raw
	c.claims = claims
	c.username = username
	hook := c.onAuthorization
	c.mu.Unlock()
	if hook != nil {
		hook(c)
	}
	return nil
}

// LoginResponse is the response to a successful login. Not every server
// version populates every field; [Client.Claims] holds the complete response.
type LoginResponse struct {
	AuthToken               string         `json:"auth_token"`
	LoginToken              string         `json:"login_token"`
	ClientIP                string         `json:"client_ip"`
	RequestablePrivs        []string       `json:"requestable_privs"`
	Username                string         `json:"username"`
	SessionID               string         `json:"session_id"`
	Roles                   []string       `json:"roles"`
	ProviderType            string         `json:"provider_type"`
	Provider                string         `json:"provider"`
	Privs                   []string       `json:"privs"`
	Options                 map[string]any `json:"options"`
	Name                    string         `json:"name"`
	LicenseInfo             map[string]any `json:"license_info"`
	ID                      int64          `json:"id"`
	Fullname                string         `json:"fullname"`
	ExternallyAuthenticated bool           `json:"externally_authenticated"`
	DevelopmentMode         bool           `json:"development_mode"`
}

// LoginOption customizes [Client.Login].
type LoginOption func(*loginRequest)

type loginRequest struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	OTPPassword string `json:"otp_password,omitempty"`
	Application string `json:"application"`
}

// WithOTP supplies a one-time password for MFA logins.
func WithOTP(otp string) LoginOption {
	return func(r *loginRequest) { r.OTPPassword = otp }
}

// WithApplication overrides the application name reported on login.
func WithApplication(app string) LoginOption {
	return func(r *loginRequest) { r.Application = app }
}

var csrfRe = regexp.MustCompile(`<meta[^>]*csrf-token[^>]*content="([^"]*)"`)

// Login authenticates with the server and establishes a session.
func (c *Client) Login(ctx context.Context, username, password string, opts ...LoginOption) (*LoginResponse, error) {
	// Fetch the root document to obtain a session cookie and CSRF token.
	root, err := c.doRequest(ctx, http.MethodGet, "/", nil, nil, "")
	if err != nil {
		return nil, err
	}
	csrf := ""
	if m := csrfRe.FindSubmatch(root); m != nil {
		csrf = string(m[1])
	}
	c.mu.Lock()
	c.csrf = csrf
	c.mu.Unlock()

	req := loginRequest{
		Username:    strings.ToLower(username),
		Password:    password,
		Application: DefaultApplication,
	}
	for _, opt := range opts {
		opt(&req)
	}
	raw, err := c.doRequest(ctx, http.MethodPost, "/sessions/login", nil, req, "")
	if err != nil {
		return nil, err
	}
	var resp LoginResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("mamori: decoding login response: %w", err)
	}
	if err := c.setAuthorization(raw, username); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Logout ends the current session. It is a no-op if not logged in.
func (c *Client) Logout(ctx context.Context) error {
	if c.Authorized() {
		if _, err := c.doRequest(ctx, http.MethodDelete, "/sessions/logout", nil, nil, ""); err != nil {
			return err
		}
	}
	return c.setAuthorization(nil, "")
}

//
// Request plumbing
//

// Call performs an authenticated request against the /api prefix (pass paths
// like "/v1/users") and returns the raw response body. For GET and DELETE,
// params are encoded into the query string (jQuery style); otherwise they are
// sent as a JSON body.
func (c *Client) Call(ctx context.Context, method, path string, params any) (json.RawMessage, error) {
	return c.doRequest(ctx, method, "/api"+path, params, params, "")
}

// CallInto is like [Client.Call] but decodes the response into out.
func (c *Client) CallInto(ctx context.Context, method, path string, params, out any) error {
	raw, err := c.Call(ctx, method, path, params)
	if err != nil {
		return err
	}
	return decode(raw, out)
}

// CallText performs an authenticated request under /api and returns the
// response body as text (for example server-sent event payloads).
func (c *Client) CallText(ctx context.Context, method, path string, params any) (string, error) {
	raw, err := c.doRequest(ctx, method, "/api"+path, params, params, "text/event-stream, text/plain, */*")
	return string(raw), err
}

// CallStream performs an authenticated request under /api and returns the
// response body as a stream. The caller must close it.
func (c *Client) CallStream(ctx context.Context, method, path string, params any) (io.ReadCloser, error) {
	resp, err := c.send(ctx, method, "/api"+path, params, params, "text/event-stream, text/plain, */*")
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

// CallBinary performs an authenticated request and returns the raw response
// bytes. path may be "/v1/..." or a full "/api/v1/..." path, and may carry its
// own query string, which is merged with params.
func (c *Client) CallBinary(ctx context.Context, method, path string, params Params) ([]byte, error) {
	path = strings.TrimPrefix(path, "/api")
	if p, q, ok := strings.Cut(path, "?"); ok {
		path = p
		vals, err := url.ParseQuery(q)
		if err != nil {
			return nil, err
		}
		merged := Params{}
		for k, v := range params {
			merged[k] = v
		}
		for k := range vals {
			merged[k] = vals.Get(k)
		}
		params = merged
	}
	var p any
	if params != nil {
		p = params
	}
	return c.doRequest(ctx, method, "/api"+path, p, p, "")
}

// CallV2 performs a request against the hub V2 API, under the /v2 prefix.
func (c *Client) CallV2(ctx context.Context, method, path string, params any) (json.RawMessage, error) {
	return c.doRequest(ctx, method, "/v2"+path, params, params, "")
}

// CallProcedure calls a hub procedure through the V2 API
// (POST /v2/call/{procedure}).
func (c *Client) CallProcedure(ctx context.Context, procedure string, args ...any) (json.RawMessage, error) {
	if args == nil {
		args = []any{}
	}
	return c.CallV2(ctx, http.MethodPost, "/call/"+procedure, Params{"args": args})
}

func (c *Client) doRequest(ctx context.Context, method, path string, query, body any, accept string) ([]byte, error) {
	resp, err := c.send(ctx, method, path, query, body, accept)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("mamori: reading response: %w", err)
	}
	return data, nil
}

// send issues the request. query is used for GET/DELETE and body otherwise.
// On a non-2xx status the body is consumed and an *APIError returned.
func (c *Client) send(ctx context.Context, method, path string, query, body any, accept string) (*http.Response, error) {
	rawPath, rawQuery, _ := strings.Cut(path, "?")
	full := strings.TrimRight(c.base.String(), "/") + rawPath

	var reader io.Reader
	if method == http.MethodGet || method == http.MethodDelete {
		extra, err := encodeQuery(query)
		if err != nil {
			return nil, err
		}
		rawQuery = joinQuery(rawQuery, extra)
	} else {
		if body != nil {
			buf, err := json.Marshal(body)
			if err != nil {
				return nil, fmt.Errorf("mamori: encoding request: %w", err)
			}
			reader = bytes.NewReader(buf)
		}
	}

	if rawQuery != "" {
		full += "?" + rawQuery
	}
	req, err := http.NewRequestWithContext(ctx, method, full, reader)
	if err != nil {
		return nil, err
	}
	if reader != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	} else {
		req.Header.Set("Accept", "application/json, text/plain, */*")
	}
	c.mu.RLock()
	if c.csrf != "" {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	c.mu.RUnlock()

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		defer resp.Body.Close()
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return nil, &APIError{
			Method:     method,
			URL:        full,
			StatusCode: resp.StatusCode,
			Status:     resp.Status,
			Body:       data,
		}
	}
	return resp, nil
}

func joinQuery(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	default:
		return a + "&" + b
	}
}

func decode(raw json.RawMessage, out any) error {
	if out == nil {
		return nil
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("mamori: decoding response: %w", err)
	}
	return nil
}

// Decode unmarshals a raw API response into a value of type T.
func Decode[T any](raw json.RawMessage) (T, error) {
	var v T
	err := decode(raw, &v)
	return v, err
}

// pathEscape escapes a path segment the way JavaScript's encodeURIComponent
// does.
func pathEscape(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}
