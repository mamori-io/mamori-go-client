package mamori

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// SSHLoginMode is how an SSH login authenticates to the remote server.
//
// The server has no mode argument: it derives the mode from the credentials
// stored with the login (a private key means key, otherwise a password means
// credentials, otherwise prompt).
type SSHLoginMode string

const (
	// SSHLoginModeKey authenticates with the private key named by
	// PrivateKeyName.
	SSHLoginModeKey SSHLoginMode = "key"
	// SSHLoginModeCredentials authenticates with the stored User and
	// Password.
	SSHLoginModeCredentials SSHLoginMode = "cred"
	// SSHLoginModePrompt asks the connecting user for credentials. It is only
	// supported for Web SSH.
	SSHLoginModePrompt SSHLoginMode = "mamori"
)

// SSHLogin is a stored SSH login (target host and credentials).
//
// A Port of 0 is treated as the default port 22, and an IdleTimeout of 0 as
// the default of 30.
//
// When LoginMode is set, Create and Update send only the credentials that mode
// uses and return an error if they are missing (or, for SSHLoginModePrompt,
// if a key or password is set). When it is empty the login is sent as is and
// the server derives the mode.
type SSHLogin struct {
	ID             string       `json:"id"`
	Name           string       `json:"name"`
	Host           string       `json:"host"`
	Port           int          `json:"port"`
	User           string       `json:"user"`
	Password       string       `json:"password"`
	PrivateKeyName string       `json:"private_key_name"`
	ThemeName      string       `json:"theme_name"`
	IdleTimeout    int          `json:"idle_timeout"`
	LoginMode      SSHLoginMode `json:"login_mode"`
}

// NewSSHLogin returns an SSH login with the default port (22) and idle
// timeout (30).
func NewSSHLogin(name string) *SSHLogin {
	return &SSHLogin{Name: name, Port: 22, IdleTimeout: 30}
}

// UnmarshalJSON decodes an SSH login record. If the record has a "uri"
// (ssh://[user@]host[:port]) the user, host and port are taken from it.
func (l *SSHLogin) UnmarshalJSON(b []byte) error {
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	looseAssign(m, l)
	if uri, ok := m["uri"].(string); ok && uri != "" {
		l.User, l.Host, l.Port = sshLoginParseURI(uri)
	}
	return nil
}

// sshLoginParseURI splits ssh://[user@]host[:port] into its parts (port
// defaults to 22).
func sshLoginParseURI(uri string) (user, host string, port int) {
	part := strings.ReplaceAll(uri, "ssh://", "")
	portStr := "22"
	if u, rest, found := strings.Cut(part, "@"); found {
		user = u
		part, _, _ = strings.Cut(rest, "@")
	}
	host = part
	if h, p, found := strings.Cut(part, ":"); found {
		host = h
		portStr, _, _ = strings.Cut(p, ":")
	}
	port, _ = strconv.Atoi(sshLoginLeadingDigits(portStr))
	return user, host, port
}

// sshLoginLeadingDigits mimics parseInt by keeping the leading digits.
func sshLoginLeadingDigits(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return s[:i]
		}
	}
	return s
}

// URI returns the ssh://[user@]host[:port] URI of the login (the port is
// omitted when it is 22).
func (l *SSHLogin) URI() string {
	port := ""
	if l.Port != 22 && l.Port != 0 {
		port = ":" + strconv.Itoa(l.Port)
	}
	if l.User != "" {
		return "ssh://" + l.User + "@" + l.Host + port
	}
	return "ssh://" + l.Host + port
}

// credentials returns the private key name and password to send for the
// login's mode, checking that the mode's required credentials are present.
func (l *SSHLogin) credentials() (key, password string, err error) {
	switch l.LoginMode {
	case "":
		return l.PrivateKeyName, l.Password, nil
	case SSHLoginModeKey:
		if l.PrivateKeyName == "" {
			return "", "", fmt.Errorf("mamori: ssh login %q: key login mode needs a private key name", l.Name)
		}
		return l.PrivateKeyName, l.Password, nil
	case SSHLoginModeCredentials:
		if l.Password == "" {
			return "", "", fmt.Errorf("mamori: ssh login %q: cred login mode needs a password", l.Name)
		}
		return "", l.Password, nil
	case SSHLoginModePrompt:
		if l.PrivateKeyName != "" || l.Password != "" {
			return "", "", fmt.Errorf("mamori: ssh login %q: mamori login mode takes no private key or password", l.Name)
		}
		return "", "", nil
	}
	return "", "", fmt.Errorf("mamori: ssh login %q: unknown login mode %q", l.Name, l.LoginMode)
}

// sqlArgs returns the SQL arguments shared by ADD_SSH_LOGIN and
// update_ssh_login after the name: uri, private key, password, theme and
// idle timeout. sep is the separator used between password and theme.
func (l *SSHLogin) sqlArgs(sep string) (string, error) {
	keyName, password, err := l.credentials()
	if err != nil {
		return "", err
	}
	key := "null"
	if keyName != "" {
		key = sqlQuote(keyName)
	}
	idle := l.IdleTimeout
	if idle == 0 {
		idle = 30
	}
	return sqlQuote(l.URI()) + ", " + key + ", " + sqlQuote(password) + sep +
		sqlQuote(l.ThemeName) + ", " + sqlQuote(strconv.Itoa(idle)), nil
}

// GetAll returns all SSH logins visible to the current user (the
// ssh_logins() procedure).
func (s *SSHLoginService) GetAll(ctx context.Context) ([]Row, error) {
	return s.client.Select(ctx, "call ssh_logins()")
}

// Create creates the SSH login and returns the first result row.
func (s *SSHLoginService) Create(ctx context.Context, l *SSHLogin) (Row, error) {
	args, err := l.sqlArgs(",")
	if err != nil {
		return nil, err
	}
	sql := "CALL ADD_SSH_LOGIN(" + sqlQuote(l.Name) + ", " + args + ")"
	return firstRow(s.client.Select(ctx, sql))
}

// Delete deletes the named SSH login and returns the first result row.
func (s *SSHLoginService) Delete(ctx context.Context, name string) (Row, error) {
	return firstRow(s.client.Select(ctx, "CALL DELETE_SSH_LOGIN("+sqlQuote(name)+")"))
}

// Update updates the SSH login identified by l.ID and returns the first
// result row.
func (s *SSHLoginService) Update(ctx context.Context, l *SSHLogin) (Row, error) {
	if l.ID == "" {
		return nil, fmt.Errorf("mamori: ssh login %q has no id", l.Name)
	}
	if err := checkSQLNumber(l.ID); err != nil {
		return nil, err
	}
	args, err := l.sqlArgs(", ")
	if err != nil {
		return nil, err
	}
	sql := "call update_ssh_login(" + l.ID + ", " + sqlQuote(l.Name) + ", " + args + ")"
	return firstRow(s.client.Select(ctx, sql))
}

// GrantTo grants use of the named SSH login to grantee.
func (s *SSHLoginService) GrantTo(ctx context.Context, name, grantee string) error {
	_, err := s.client.Permissions.Grant(ctx, NewSSHLoginPermission(name, grantee))
	return err
}

// RevokeFrom revokes use of the named SSH login from grantee.
func (s *SSHLoginService) RevokeFrom(ctx context.Context, name, grantee string) error {
	_, err := s.client.Permissions.Revoke(ctx, NewSSHLoginPermission(name, grantee))
	return err
}
