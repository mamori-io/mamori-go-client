package mamori

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
)

// RemoteDesktopProtocol is the protocol of a remote desktop login.
type RemoteDesktopProtocol string

// Remote desktop protocols.
const (
	RemoteDesktopProtocolRDP RemoteDesktopProtocol = "rdp"
	RemoteDesktopProtocolVNC RemoteDesktopProtocol = "vnc"
)

// RemoteDesktopLoginMode is how the remote desktop user is authenticated.
type RemoteDesktopLoginMode string

// Remote desktop login modes.
const (
	// RemoteDesktopLoginModeManual uses the stored username and password.
	RemoteDesktopLoginModeManual RemoteDesktopLoginMode = "manual"
	// RemoteDesktopLoginModeOSPrompt lets the remote OS prompt for credentials.
	RemoteDesktopLoginModeOSPrompt RemoteDesktopLoginMode = "os"
	// RemoteDesktopLoginModeMamoriPrompt has mamori prompt for credentials.
	RemoteDesktopLoginModeMamoriPrompt RemoteDesktopLoginMode = "mamori"
)

// RemoteDesktopKeyboardLayout is an RDP server keyboard layout.
type RemoteDesktopKeyboardLayout string

// RDP server keyboard layouts.
const (
	RemoteDesktopKeyboardUnspecified         RemoteDesktopKeyboardLayout = ""
	RemoteDesktopKeyboardBrazilianPortuguese RemoteDesktopKeyboardLayout = "pt-br-qwerty"
	RemoteDesktopKeyboardEnglishUK           RemoteDesktopKeyboardLayout = "en-gb-qwerty"
	RemoteDesktopKeyboardEnglishUS           RemoteDesktopKeyboardLayout = "en-us-qwerty"
	RemoteDesktopKeyboardFrench              RemoteDesktopKeyboardLayout = "fr-fr-azerty"
	RemoteDesktopKeyboardFrenchBelgian       RemoteDesktopKeyboardLayout = "fr-be-azerty"
	RemoteDesktopKeyboardFrenchSwiss         RemoteDesktopKeyboardLayout = "fr-ch-qwertz"
	RemoteDesktopKeyboardGerman              RemoteDesktopKeyboardLayout = "de-de-qwertz"
	RemoteDesktopKeyboardGermanSwiss         RemoteDesktopKeyboardLayout = "de-ch-qwertz"
	RemoteDesktopKeyboardHungarian           RemoteDesktopKeyboardLayout = "hu-hu-qwertz"
	RemoteDesktopKeyboardItalian             RemoteDesktopKeyboardLayout = "it-it-qwerty"
	RemoteDesktopKeyboardJapanese            RemoteDesktopKeyboardLayout = "ja-jp-qwerty"
	RemoteDesktopKeyboardNorwegian           RemoteDesktopKeyboardLayout = "no-no-qwerty"
	RemoteDesktopKeyboardSpanish             RemoteDesktopKeyboardLayout = "es-es-qwerty"
	RemoteDesktopKeyboardSpanishLatinAmerica RemoteDesktopKeyboardLayout = "es-latam-qwerty"
	RemoteDesktopKeyboardSwedish             RemoteDesktopKeyboardLayout = "sv-se-qwerty"
	RemoteDesktopKeyboardTurkishQ            RemoteDesktopKeyboardLayout = "tr-tr-qwerty"
	RemoteDesktopKeyboardUnicodeFailsafe     RemoteDesktopKeyboardLayout = "failsafe"
)

// RemoteDesktopClipboardMode controls line ending normalisation of the
// clipboard.
type RemoteDesktopClipboardMode string

// Clipboard modes.
const (
	RemoteDesktopClipboardPreserve             RemoteDesktopClipboardMode = "preserve"
	RemoteDesktopClipboardConvertToUnixLF      RemoteDesktopClipboardMode = "unix"
	RemoteDesktopClipboardConvertToWindowsCRLF RemoteDesktopClipboardMode = "windows"
)

// RemoteDesktopColorDepth is an RDP color depth in bits per pixel.
type RemoteDesktopColorDepth int

// RDP color depths.
const (
	RemoteDesktopColors256 RemoteDesktopColorDepth = 8
	RemoteDesktopColors64K RemoteDesktopColorDepth = 16
	RemoteDesktopColors16M RemoteDesktopColorDepth = 24
)

// RemoteDesktopAuthenticationMode is the RDP security mode.
type RemoteDesktopAuthenticationMode string

// RDP security modes.
const (
	RemoteDesktopAuthAny                                RemoteDesktopAuthenticationMode = "any"
	RemoteDesktopAuthNetworkLevelAuthentication         RemoteDesktopAuthenticationMode = "nla"
	RemoteDesktopAuthExtendedNetworkLevelAuthentication RemoteDesktopAuthenticationMode = "nla-ext"
	RemoteDesktopAuthLegacyRDP                          RemoteDesktopAuthenticationMode = "rdp"
)

// VNCOptions are the connection settings of a VNC login.
type VNCOptions struct {
	Hostname            string `json:"hostname"`
	Port                int    `json:"port"`
	Username            string `json:"username"`
	Password            string `json:"password"`
	Width               int    `json:"width"`
	Height              int    `json:"height"`
	CredentialsRequired bool   `json:"_credentials_required"`
}

// NewVNCOptions returns VNC settings with the TypeScript SDK defaults.
func NewVNCOptions() *VNCOptions {
	return &VNCOptions{Port: 3389, Width: 1024, Height: 768}
}

// UnmarshalJSON decodes VNC settings, tolerating string numbers.
func (o *VNCOptions) UnmarshalJSON(b []byte) error { return looseUnmarshal(b, o) }

// RDPOptions are the connection settings of an RDP login.
type RDPOptions struct {
	Hostname                 string                          `json:"hostname"`
	Port                     int                             `json:"port"`
	Username                 string                          `json:"username"`
	Password                 string                          `json:"password"`
	Domain                   string                          `json:"domain"`
	CredentialsRequired      bool                            `json:"_credentials_required"`
	Width                    int                             `json:"width"`
	Height                   int                             `json:"height"`
	Security                 RemoteDesktopAuthenticationMode `json:"security"`
	IgnoreCert               bool                            `json:"ignore_cert"`
	Console                  bool                            `json:"console"`
	InitialProgram           string                          `json:"initial_program"`
	ServerLayout             RemoteDesktopKeyboardLayout     `json:"server_layout"`
	ColorDepth               RemoteDesktopColorDepth         `json:"color_depth"`
	ForceLossless            bool                            `json:"force_lossless"`
	EnableFontSmoothing      bool                            `json:"enable_font_smoothing"`
	EnableWallpaper          bool                            `json:"enable_wallpaper"`
	EnableTheming            bool                            `json:"enable_theming"`
	EnableFullWindowDrag     bool                            `json:"enable_full_window_drag"`
	EnableDesktopComposition bool                            `json:"enable_desktop_composition"`
	EnableMenuAnimations     bool                            `json:"enable_menu_animations"`
	DisableCopy              bool                            `json:"disable_copy"`
	DisablePaste             bool                            `json:"disable_paste"`
	NormalizeClipboard       RemoteDesktopClipboardMode      `json:"normalize_clipboard"`
}

// NewRDPOptions returns RDP settings with the TypeScript SDK defaults.
func NewRDPOptions() *RDPOptions {
	return &RDPOptions{
		Port:                3389,
		Width:               1024,
		Height:              768,
		Security:            RemoteDesktopAuthAny,
		IgnoreCert:          true,
		ServerLayout:        RemoteDesktopKeyboardEnglishUS,
		ColorDepth:          RemoteDesktopColors16M,
		EnableFontSmoothing: true,
		NormalizeClipboard:  RemoteDesktopClipboardConvertToWindowsCRLF,
	}
}

// UnmarshalJSON decodes RDP settings, tolerating string numbers and bools.
func (o *RDPOptions) UnmarshalJSON(b []byte) error { return looseUnmarshal(b, o) }

// RemoteDesktopLogin is a stored RDP or VNC login. Exactly one of RDP and
// VNC is set, matching Protocol; use [RemoteDesktopLogin.SetProtocol] to
// switch.
//
// Its JSON form is flat: name, id, protocol and record followed by the fields
// of the active protocol's options (an "rdp" or "vnc" object is also
// accepted when decoding).
type RemoteDesktopLogin struct {
	// ID is the server id, -1 if not yet known.
	ID       int
	Name     string
	Protocol RemoteDesktopProtocol
	// Record enables session recording.
	Record bool
	RDP    *RDPOptions
	VNC    *VNCOptions
}

// NewRemoteDesktopLogin returns a login with default settings for protocol
// and session recording enabled.
func NewRemoteDesktopLogin(name string, protocol RemoteDesktopProtocol) *RemoteDesktopLogin {
	l := &RemoteDesktopLogin{ID: -1, Name: name, Record: true}
	l.SetProtocol(protocol)
	return l
}

// SetProtocol switches the login to protocol, creating default options for
// it if needed and dropping the other protocol's options. Unknown protocols
// are ignored.
func (l *RemoteDesktopLogin) SetProtocol(p RemoteDesktopProtocol) {
	switch p {
	case RemoteDesktopProtocolRDP:
		l.Protocol = p
		l.VNC = nil
		if l.RDP == nil {
			l.RDP = NewRDPOptions()
		}
	case RemoteDesktopProtocolVNC:
		l.Protocol = p
		l.RDP = nil
		if l.VNC == nil {
			l.VNC = NewVNCOptions()
		}
	}
}

// DefaultSettings resets the options of the current protocol to defaults.
func (l *RemoteDesktopLogin) DefaultSettings() {
	if l.Protocol == RemoteDesktopProtocolVNC {
		l.VNC, l.RDP = NewVNCOptions(), nil
	} else {
		l.RDP, l.VNC = NewRDPOptions(), nil
	}
}

// ensureOptions makes sure the options for the current protocol exist.
func (l *RemoteDesktopLogin) ensureOptions() {
	p := l.Protocol
	if p == "" {
		p = RemoteDesktopProtocolRDP
	}
	l.SetProtocol(p)
}

// At sets the host and port to connect to.
func (l *RemoteDesktopLogin) At(host string, port int) {
	l.ensureOptions()
	if l.RDP != nil {
		l.RDP.Hostname, l.RDP.Port = host, port
	} else {
		l.VNC.Hostname, l.VNC.Port = host, port
	}
}

// SetCredentials sets the stored credentials. domain is used for RDP only.
func (l *RemoteDesktopLogin) SetCredentials(user, password, domain string) {
	l.ensureOptions()
	if l.RDP != nil {
		l.RDP.Username, l.RDP.Password, l.RDP.Domain = user, password, domain
	} else {
		l.VNC.Username, l.VNC.Password = user, password
	}
}

// credFields returns pointers to the credential settings of the active
// protocol.
func (l *RemoteDesktopLogin) credFields() (credRequired *bool, user, password *string) {
	l.ensureOptions()
	if l.RDP != nil {
		return &l.RDP.CredentialsRequired, &l.RDP.Username, &l.RDP.Password
	}
	return &l.VNC.CredentialsRequired, &l.VNC.Username, &l.VNC.Password
}

// SetLoginMode sets how users are authenticated. All modes clear the stored
// username and password; set credentials afterwards for
// RemoteDesktopLoginModeManual.
func (l *RemoteDesktopLogin) SetLoginMode(mode RemoteDesktopLoginMode) {
	req, user, pw := l.credFields()
	switch mode {
	case RemoteDesktopLoginModeManual, RemoteDesktopLoginModeMamoriPrompt:
		*req, *user, *pw = true, "", ""
	case RemoteDesktopLoginModeOSPrompt:
		*req, *user, *pw = false, "", ""
	}
}

// LoginMode reports how users are authenticated.
func (l *RemoteDesktopLogin) LoginMode() RemoteDesktopLoginMode {
	req, user, _ := l.credFields()
	if *req {
		if *user != "" {
			return RemoteDesktopLoginModeManual
		}
		return RemoteDesktopLoginModeMamoriPrompt
	}
	return RemoteDesktopLoginModeOSPrompt
}

// optionsMap returns the active protocol's options as a map.
func (l *RemoteDesktopLogin) optionsMap() (Params, error) {
	l.ensureOptions()
	var opts any = l.RDP
	if l.RDP == nil {
		opts = l.VNC
	}
	b, err := json.Marshal(opts)
	if err != nil {
		return nil, err
	}
	m := Params{}
	err = json.Unmarshal(b, &m)
	return m, err
}

// MarshalJSON encodes the login in its flat form.
func (l RemoteDesktopLogin) MarshalJSON() ([]byte, error) {
	m, err := l.optionsMap()
	if err != nil {
		return nil, err
	}
	m["name"] = l.Name
	m["id"] = l.ID
	m["protocol"] = l.Protocol
	m["record"] = l.Record
	return json.Marshal(m)
}

// UnmarshalJSON decodes a login from its flat form. The server's detail
// keys _id, _protocol and _record_session are accepted as well.
func (l *RemoteDesktopLogin) UnmarshalJSON(b []byte) error {
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	remoteDesktopRename(m, "_id", "id")
	remoteDesktopRename(m, "_protocol", "protocol")
	remoteDesktopRename(m, "_record_session", "record")

	if l.ID == 0 {
		l.ID = -1
	}
	if name, ok := m["name"].(string); ok {
		l.Name = name
	}
	if v, ok := m["id"]; ok {
		var id struct {
			ID int `json:"id"`
		}
		looseAssign(Params{"id": v}, &id)
		l.ID = id.ID
		if v == nil || id.ID == 0 {
			l.ID = -1
		}
	}
	if p, ok := m["protocol"].(string); ok {
		l.SetProtocol(RemoteDesktopProtocol(p))
	}
	l.ensureOptions()
	if v, ok := m["record"]; ok {
		var rec struct {
			Record bool `json:"record"`
		}
		looseAssign(Params{"record": v}, &rec)
		l.Record = rec.Record
	}

	if l.RDP != nil {
		if nested, ok := m["rdp"].(map[string]any); ok {
			l.RDP = &RDPOptions{}
			looseAssign(nested, l.RDP)
		} else {
			looseAssign(m, l.RDP)
		}
	} else {
		if nested, ok := m["vnc"].(map[string]any); ok {
			l.VNC = &VNCOptions{}
			looseAssign(nested, l.VNC)
		} else {
			looseAssign(m, l.VNC)
		}
	}
	return nil
}

func remoteDesktopRename(m map[string]any, from, to string) {
	if v, ok := m[from]; ok {
		if _, exists := m[to]; !exists {
			m[to] = v
		}
		delete(m, from)
	}
}

// details returns the create/update "details" payload: the active options
// plus _protocol and _record_session.
func (l *RemoteDesktopLogin) details() (Params, error) {
	m, err := l.optionsMap()
	if err != nil {
		return nil, err
	}
	m["_protocol"] = l.Protocol
	m["_record_session"] = l.Record
	return m, nil
}

// List searches remote desktop logins visible to the current user.
func (s *RemoteDesktopService) List(ctx context.Context, opts SearchOptions) (*SearchResult[Params], error) {
	var res SearchResult[Params]
	if err := s.client.CallInto(ctx, http.MethodGet, "/v1/rdp", opts.params(), &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// GetByName returns the details of the named remote desktop login.
func (s *RemoteDesktopService) GetByName(ctx context.Context, name string) (*RemoteDesktopLogin, error) {
	raw, err := s.client.Call(ctx, http.MethodGet, "/v1/rdp/"+pathEscape(name), nil)
	if err != nil {
		return nil, err
	}
	l := &RemoteDesktopLogin{ID: -1, Name: name, Record: true}
	if err := decode(raw, l); err != nil {
		return nil, err
	}
	return l, nil
}

// Create creates the remote desktop login.
func (s *RemoteDesktopService) Create(ctx context.Context, l *RemoteDesktopLogin) (json.RawMessage, error) {
	d, err := l.details()
	if err != nil {
		return nil, err
	}
	return s.client.Call(ctx, http.MethodPost, "/v1/rdp/", Params{"name": l.Name, "details": d})
}

// Update updates the remote desktop login identified by l.ID.
func (s *RemoteDesktopService) Update(ctx context.Context, l *RemoteDesktopLogin) (json.RawMessage, error) {
	d, err := l.details()
	if err != nil {
		return nil, err
	}
	return s.client.Call(ctx, http.MethodPut, "/v1/rdp/"+strconv.Itoa(l.ID), Params{"name": l.Name, "details": d})
}

// Delete deletes the named remote desktop login.
func (s *RemoteDesktopService) Delete(ctx context.Context, name string) (json.RawMessage, error) {
	return s.client.Call(ctx, http.MethodDelete, "/v1/rdp/"+pathEscape(name), nil)
}

// GrantTo grants use of the named remote desktop login to grantee.
func (s *RemoteDesktopService) GrantTo(ctx context.Context, name, grantee string) error {
	_, err := s.client.Permissions.Grant(ctx, NewRemoteDesktopLoginPermission(name, grantee))
	return err
}

// RevokeFrom revokes use of the named remote desktop login from grantee.
func (s *RemoteDesktopService) RevokeFrom(ctx context.Context, name, grantee string) error {
	_, err := s.client.Permissions.Revoke(ctx, NewRemoteDesktopLoginPermission(name, grantee))
	return err
}
