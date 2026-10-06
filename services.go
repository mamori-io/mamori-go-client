package mamori

// Resource services. Each is a view of the client; methods live in the file
// for that resource.

// AlertChannelService manages alert channels.
type AlertChannelService service

// ConnectionLogService queries connection logs.
type ConnectionLogService service

// DatasourceService manages datasources.
type DatasourceService service

// DBCredentialService manages datasource credentials.
type DBCredentialService service

// EventHandlerService manages event handlers.
type EventHandlerService service

// HTTPResourceService manages HTTP resources.
type HTTPResourceService service

// IPResourceService manages IP resources.
type IPResourceService service

// KeyService manages encryption and SSH keys.
type KeyService service

// NetworkService manages networks (IPSec, OpenVPN, SSH tunnels).
type NetworkService service

// OnDemandPolicyService manages on-demand policies.
type OnDemandPolicyService service

// PermissionService grants, revokes and lists permissions.
type PermissionService service

// PolicyService manages access policies.
type PolicyService service

// ProviderService manages authentication providers.
type ProviderService service

// RemoteDesktopService manages remote desktop logins.
type RemoteDesktopService service

// RequestableResourceService manages requestable resources.
type RequestableResourceService service

// RoleService manages roles.
type RoleService service

// ScriptFlowService manages script flows.
type ScriptFlowService service

// ScriptService manages scripts.
type ScriptService service

// SecretService manages secrets.
type SecretService service

// ServerSettingsService manages server-wide settings.
type ServerSettingsService service

// SQLMaskingPolicyService manages SQL masking policies.
type SQLMaskingPolicyService service

// SSHLoginService manages SSH logins.
type SSHLoginService service

// UserService manages mamori users.
type UserService service

// WireguardPeerService manages wireguard peers.
type WireguardPeerService service
