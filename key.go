package mamori

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

// KeyType is the kind of a named key.
type KeyType string

// Key types.
const (
	KeyTypeAES KeyType = "AES"
	KeyTypeRSA KeyType = "RSA"
	KeyTypeSSH KeyType = "SSH"
)

// SSHAlgorithm is the algorithm of a generated SSH key.
type SSHAlgorithm string

// SSH key algorithms.
const (
	SSHAlgorithmRSA     SSHAlgorithm = "RSA"
	SSHAlgorithmDSA     SSHAlgorithm = "DSA"
	SSHAlgorithmECDSA   SSHAlgorithm = "ECDSA"
	SSHAlgorithmED25519 SSHAlgorithm = "ED25519"
)

// KeyDefaultSize is the key size used when generating RSA and SSH keys if
// Key.Size is zero.
const KeyDefaultSize = 1024

// Key is a named cryptographic key.
type Key struct {
	// Name is the unique key name.
	Name string `json:"name"`
	// Type is the key type.
	Type KeyType `json:"type,omitempty"`
	// Key is the key text, e.g. a PEM block. For SSH keys it may be the
	// private key, the public key or both. Leave empty to generate a key.
	Key string `json:"key,omitempty"`
	// Password optionally protects the key.
	Password string `json:"password,omitempty"`
	// Size is the size of generated RSA/SSH keys (default 1024; ED25519
	// keys are always 256).
	Size int `json:"size,omitempty"`
	// Algorithm is the algorithm of generated SSH keys.
	Algorithm SSHAlgorithm `json:"algorithm,omitempty"`
}

// NewKey returns a key with the default size.
func NewKey(name string, keyType KeyType) *Key {
	return &Key{Name: name, Type: keyType, Size: KeyDefaultSize}
}

func (k *Key) size() int {
	if k.Size == 0 {
		return KeyDefaultSize
	}
	return k.Size
}

// GetAll returns the keys visible to the logged-in user. Records include
// fields such as name, type, usage and public_key.
func (s *KeyService) GetAll(ctx context.Context) ([]Row, error) {
	raw, err := s.client.Call(ctx, http.MethodGet, "/v1/encryption_keys", nil)
	if err != nil {
		return nil, err
	}
	return decodeRows(raw)
}

// Create creates the key.
//
// For AES with no key value a random key is generated. For RSA with no key
// value a key pair of k.Size is generated, named "<name>_public" and
// "<name>_private", and the public key is returned. For SSH with no key
// value a key of k.Algorithm is generated and its public key returned.
func (s *KeyService) Create(ctx context.Context, k *Key) (json.RawMessage, error) {
	switch {
	case k.Type == KeyTypeRSA && k.Key == "":
		return s.client.Call(ctx, http.MethodPost, "/v1/encryption_keys/create/rsapair", Params{
			"name": k.Name,
			"size": k.size(),
		})
	case k.Type == KeyTypeSSH && k.Key == "":
		size := k.size()
		if k.Algorithm == SSHAlgorithmED25519 {
			size = 256
		}
		p := Params{"name": k.Name, "size": size}
		if k.Algorithm != "" {
			p["algorithm"] = k.Algorithm
		}
		return s.client.Call(ctx, http.MethodPost, "/v1/encryption_keys/create/sshkey", p)
	}
	p := Params{"name": k.Name}
	if k.Type != "" {
		p["type"] = k.Type
	}
	if k.Password != "" {
		p["password"] = k.Password
	}
	if k.Key != "" {
		p["value"] = k.Key
	}
	return s.client.Call(ctx, http.MethodPost, "/v1/encryption_keys", p)
}

// Delete deletes the named key.
func (s *KeyService) Delete(ctx context.Context, name string) (json.RawMessage, error) {
	return s.client.Call(ctx, http.MethodDelete, "/v1/encryption_keys/"+pathEscape(name), nil)
}

// Rename renames a key.
func (s *KeyService) Rename(ctx context.Context, name, newName string) (json.RawMessage, error) {
	return s.client.Call(ctx, http.MethodPut, "/v1/encryption_keys/"+pathEscape(name), Params{"name": newName})
}

// Update replaces the value of the named key, keeping its password.
func (s *KeyService) Update(ctx context.Context, name, value string) (json.RawMessage, error) {
	return s.client.Call(ctx, http.MethodPut, "/v1/encryption_keys/"+pathEscape(name), value)
}

func keyGranteePath(grantee string) string {
	return "/v1/grantee/" + pathEscape(strings.ToLower(grantee)) + "/encryption_keys"
}

// GrantTo grants use of the named key to grantee. The server answers
// "Granted".
func (s *KeyService) GrantTo(ctx context.Context, name, grantee string) (json.RawMessage, error) {
	return s.client.Call(ctx, http.MethodPost, keyGranteePath(grantee), Params{"encryption_keys": []string{name}})
}

// RevokeFrom revokes use of the named key from grantee. The server answers
// "Revoked".
func (s *KeyService) RevokeFrom(ctx context.Context, name, grantee string) (json.RawMessage, error) {
	return s.client.Call(ctx, http.MethodDelete, keyGranteePath(grantee), Params{"encryption_keys": []string{name}})
}
