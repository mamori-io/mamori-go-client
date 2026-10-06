package mamori

import (
	"fmt"
	"strconv"
	"strings"
)

// DBPermission is a datasource (database) privilege.
type DBPermission string

// Datasource privileges.
const (
	DBPermissionSelect          DBPermission = "SELECT"
	DBPermissionInsert          DBPermission = "INSERT"
	DBPermissionUpdate          DBPermission = "UPDATE"
	DBPermissionDelete          DBPermission = "DELETE"
	DBPermissionTruncate        DBPermission = "TRUNCATE"
	DBPermissionCreateTable     DBPermission = "CREATE TABLE"
	DBPermissionDropTable       DBPermission = "DROP TABLE"
	DBPermissionAlterTable      DBPermission = "ALTER TABLE"
	DBPermissionCreateView      DBPermission = "CREATE VIEW"
	DBPermissionDropView        DBPermission = "DROP VIEW"
	DBPermissionCreateSchema    DBPermission = "CREATE SCHEMA"
	DBPermissionDropSchema      DBPermission = "DROP SCHEMA"
	DBPermissionPassthrough     DBPermission = "PASSTHROUGH"
	DBPermissionMasked          DBPermission = "MASKED PASSTHROUGH"
	DBPermissionProtected       DBPermission = "PROTECTED PASSTHROUGH"
	DBPermissionReveal          DBPermission = "REVEAL"
	DBPermissionCall            DBPermission = "CALL"
	DBPermissionExecuteSQLBlock DBPermission = "EXECUTE SQL BLOCK"
)

// dbPermissions lists every [DBPermission] (used by [PermissionFromRecord]).
var dbPermissions = []DBPermission{
	DBPermissionSelect, DBPermissionInsert, DBPermissionUpdate, DBPermissionDelete,
	DBPermissionTruncate, DBPermissionCreateTable, DBPermissionDropTable,
	DBPermissionAlterTable, DBPermissionCreateView, DBPermissionDropView,
	DBPermissionCreateSchema, DBPermissionDropSchema, DBPermissionPassthrough,
	DBPermissionMasked, DBPermissionProtected, DBPermissionReveal, DBPermissionCall,
	DBPermissionExecuteSQLBlock,
}

// MamoriPrivilege is a mamori server privilege.
type MamoriPrivilege string

// Mamori server privileges.
const (
	MamoriPrivilegeAlert                            MamoriPrivilege = "ALERT"
	MamoriPrivilegeAllPrivileges                    MamoriPrivilege = "ALL PRIVILEGES"
	MamoriPrivilegeAlterDriver                      MamoriPrivilege = "ALTER DRIVER"
	MamoriPrivilegeAlterLicenseKey                  MamoriPrivilege = "ALTER LICENSE KEY"
	MamoriPrivilegeAlterPolicy                      MamoriPrivilege = "ALTER POLICY"
	MamoriPrivilegeAlterUser                        MamoriPrivilege = "ALTER USER"
	MamoriPrivilegeCancelSession                    MamoriPrivilege = "CANCEL SESSION"
	MamoriPrivilegeCheckPermission                  MamoriPrivilege = "CHECK PERMISSION"
	MamoriPrivilegeClearCache                       MamoriPrivilege = "CLEAR CACHE"
	MamoriPrivilegeConnect                          MamoriPrivilege = "CONNECT"
	MamoriPrivilegeCopyUser                         MamoriPrivilege = "COPY USER"
	MamoriPrivilegeCreateBackup                     MamoriPrivilege = "CREATE BACKUP"
	MamoriPrivilegeCreateDriver                     MamoriPrivilege = "CREATE DRIVER"
	MamoriPrivilegeCreateIPResource                 MamoriPrivilege = "CREATE IP RESOURCE"
	MamoriPrivilegeCreateJob                        MamoriPrivilege = "CREATE JOB"
	MamoriPrivilegeCreateJobOwner                   MamoriPrivilege = "CREATE JOB OWNER"
	MamoriPrivilegeCreateProject                    MamoriPrivilege = "CREATE PROJECT"
	MamoriPrivilegeCreateRole                       MamoriPrivilege = "CREATE ROLE"
	MamoriPrivilegeCreateSystem                     MamoriPrivilege = "CREATE SYSTEM"
	MamoriPrivilegeCreateTableWithoutDestination    MamoriPrivilege = "CREATE TABLE WITHOUT DESTINATION"
	MamoriPrivilegeCreateUser                       MamoriPrivilege = "CREATE USER"
	MamoriPrivilegeDisableConnectionLog             MamoriPrivilege = "DISABLE CONNECTION LOG"
	MamoriPrivilegeDisableUser                      MamoriPrivilege = "DISABLE USER"
	MamoriPrivilegeDropDriver                       MamoriPrivilege = "DROP DRIVER"
	MamoriPrivilegeDropJob                          MamoriPrivilege = "DROP JOB"
	MamoriPrivilegeDropRole                         MamoriPrivilege = "DROP ROLE"
	MamoriPrivilegeDropUser                         MamoriPrivilege = "DROP USER"
	MamoriPrivilegeExecuteAs                        MamoriPrivilege = "EXECUTE AS"
	MamoriPrivilegeExecuteJob                       MamoriPrivilege = "EXECUTE JOB"
	MamoriPrivilegeExecuteProcedure                 MamoriPrivilege = "EXECUTE PROCEDURE"
	MamoriPrivilegeGrantRole                        MamoriPrivilege = "GRANT ROLE"
	MamoriPrivilegeIPScan                           MamoriPrivilege = "IP SCAN"
	MamoriPrivilegeJMXAccess                        MamoriPrivilege = "JMX ACCESS"
	MamoriPrivilegeLogAccess                        MamoriPrivilege = "LOG ACCESS"
	MamoriPrivilegeLogSession                       MamoriPrivilege = "LOG SESSION"
	MamoriPrivilegeMamoriCatalog                    MamoriPrivilege = "MAMORI CATALOG"
	MamoriPrivilegeMamoriSecurityCatalog            MamoriPrivilege = "MAMORI SECURITY CATALOG"
	MamoriPrivilegeManageDatasourceGroups           MamoriPrivilege = "MANAGE DATASOURCE GROUPS"
	MamoriPrivilegeMaskingRuleAdmin                 MamoriPrivilege = "MASKING RULE ADMIN"
	MamoriPrivilegeMonitorAdmin                     MamoriPrivilege = "MONITOR ADMIN"
	MamoriPrivilegeMonitorEditor                    MamoriPrivilege = "MONITOR EDITOR"
	MamoriPrivilegeMonitorViewer                    MamoriPrivilege = "MONITOR VIEWER"
	MamoriPrivilegePolicy                           MamoriPrivilege = "POLICY"
	MamoriPrivilegeQueryConsoleAccess               MamoriPrivilege = "QUERY CONSOLE ACCESS"
	MamoriPrivilegeRequest                          MamoriPrivilege = "REQUEST"
	MamoriPrivilegeRestartServer                    MamoriPrivilege = "RESTART SERVER"
	MamoriPrivilegeRestrictUser                     MamoriPrivilege = "RESTRICT USER"
	MamoriPrivilegeRevokeRole                       MamoriPrivilege = "REVOKE ROLE"
	MamoriPrivilegeRule                             MamoriPrivilege = "RULE"
	MamoriPrivilegeSetDefaultAuthenticationProvider MamoriPrivilege = "SET DEFAULT AUTHENTICATION PROVIDER"
	MamoriPrivilegeSetDescribe                      MamoriPrivilege = "SET DESCRIBE"
	MamoriPrivilegeSetLoggingLevel                  MamoriPrivilege = "SET LOGGING_LEVEL"
	MamoriPrivilegeSetNumberOfMappers               MamoriPrivilege = "SET NUMBEROFMAPPERS"
	MamoriPrivilegeSetNumberOfRDBMSTransferThreads  MamoriPrivilege = "SET NUMBEROFRDBMSTRANSFERTHREADS"
	MamoriPrivilegeSetNumberOfReducers              MamoriPrivilege = "SET NUMBEROFREDUCERS"
	MamoriPrivilegeSetNumSqoopMapTasks              MamoriPrivilege = "SET NUMSQOOPMAPTASKS"
	MamoriPrivilegeSetPauseCleanup                  MamoriPrivilege = "SET PAUSECLEANUP"
	MamoriPrivilegeSetRunMode                       MamoriPrivilege = "SET RUNMODE"
	MamoriPrivilegeSetServerName                    MamoriPrivilege = "SET SERVER_NAME"
	MamoriPrivilegeSetSqoopOptions                  MamoriPrivilege = "SET SQOOP OPTIONS"
	MamoriPrivilegeSetSystemProperty                MamoriPrivilege = "SET SYSTEM PROPERTY"
	MamoriPrivilegeSystemMonitor                    MamoriPrivilege = "SYSTEM MONITOR"
	MamoriPrivilegeValidateUser                     MamoriPrivilege = "VALIDATE USER"
	MamoriPrivilegeViewAllUserLogs                  MamoriPrivilege = "VIEW ALL USER LOGS"
	MamoriPrivilegeViewClearSQLErrorLog             MamoriPrivilege = "VIEW CLEAR SQL ERROR LOG"
	MamoriPrivilegeViewClearSQLLog                  MamoriPrivilege = "VIEW CLEAR SQL LOG"
	MamoriPrivilegeWebAutoCommit                    MamoriPrivilege = "WEB AUTO COMMIT"
	MamoriPrivilegeWebExportData                    MamoriPrivilege = "WEB EXPORT DATA"
	MamoriPrivilegeWebSQLEditor                     MamoriPrivilege = "WEB SQL EDITOR"
	MamoriPrivilegeAlterEncryptionKey               MamoriPrivilege = "ALTER ENCRYPTION KEY"
	MamoriPrivilegeCreateEncryptionKey              MamoriPrivilege = "CREATE ENCRYPTION KEY"
	MamoriPrivilegeDropEncryptionKey                MamoriPrivilege = "DROP ENCRYPTION KEY"
)

// mamoriPrivileges lists every [MamoriPrivilege] (used by [PermissionFromRecord]).
var mamoriPrivileges = []MamoriPrivilege{
	MamoriPrivilegeAlert, MamoriPrivilegeAllPrivileges, MamoriPrivilegeAlterDriver,
	MamoriPrivilegeAlterLicenseKey, MamoriPrivilegeAlterPolicy, MamoriPrivilegeAlterUser,
	MamoriPrivilegeCancelSession, MamoriPrivilegeCheckPermission, MamoriPrivilegeClearCache,
	MamoriPrivilegeConnect, MamoriPrivilegeCopyUser, MamoriPrivilegeCreateBackup,
	MamoriPrivilegeCreateDriver, MamoriPrivilegeCreateIPResource, MamoriPrivilegeCreateJob,
	MamoriPrivilegeCreateJobOwner, MamoriPrivilegeCreateProject, MamoriPrivilegeCreateRole,
	MamoriPrivilegeCreateSystem, MamoriPrivilegeCreateTableWithoutDestination,
	MamoriPrivilegeCreateUser, MamoriPrivilegeDisableConnectionLog, MamoriPrivilegeDisableUser,
	MamoriPrivilegeDropDriver, MamoriPrivilegeDropJob, MamoriPrivilegeDropRole,
	MamoriPrivilegeDropUser, MamoriPrivilegeExecuteAs, MamoriPrivilegeExecuteJob,
	MamoriPrivilegeExecuteProcedure, MamoriPrivilegeGrantRole, MamoriPrivilegeIPScan,
	MamoriPrivilegeJMXAccess, MamoriPrivilegeLogAccess, MamoriPrivilegeLogSession,
	MamoriPrivilegeMamoriCatalog, MamoriPrivilegeMamoriSecurityCatalog,
	MamoriPrivilegeManageDatasourceGroups, MamoriPrivilegeMaskingRuleAdmin,
	MamoriPrivilegeMonitorAdmin, MamoriPrivilegeMonitorEditor, MamoriPrivilegeMonitorViewer,
	MamoriPrivilegePolicy, MamoriPrivilegeQueryConsoleAccess, MamoriPrivilegeRequest,
	MamoriPrivilegeRestartServer, MamoriPrivilegeRestrictUser, MamoriPrivilegeRevokeRole,
	MamoriPrivilegeRule, MamoriPrivilegeSetDefaultAuthenticationProvider,
	MamoriPrivilegeSetDescribe, MamoriPrivilegeSetLoggingLevel, MamoriPrivilegeSetNumberOfMappers,
	MamoriPrivilegeSetNumberOfRDBMSTransferThreads, MamoriPrivilegeSetNumberOfReducers,
	MamoriPrivilegeSetNumSqoopMapTasks, MamoriPrivilegeSetPauseCleanup, MamoriPrivilegeSetRunMode,
	MamoriPrivilegeSetServerName, MamoriPrivilegeSetSqoopOptions, MamoriPrivilegeSetSystemProperty,
	MamoriPrivilegeSystemMonitor, MamoriPrivilegeValidateUser, MamoriPrivilegeViewAllUserLogs,
	MamoriPrivilegeViewClearSQLErrorLog, MamoriPrivilegeViewClearSQLLog,
	MamoriPrivilegeWebAutoCommit, MamoriPrivilegeWebExportData, MamoriPrivilegeWebSQLEditor,
	MamoriPrivilegeAlterEncryptionKey, MamoriPrivilegeCreateEncryptionKey,
	MamoriPrivilegeDropEncryptionKey,
}

// permissionQuote wraps s in double quotes.
func permissionQuote(s string) string { return `"` + s + `"` }

// permissionGrantables returns the single element list [item], or an empty
// list when item is empty.
func permissionGrantables(item string) []string {
	if item == "" {
		return []string{}
	}
	return []string{item}
}

// permissionNamed returns the "grantables" + "object_name" options shared by
// the permissions on a single named object.
func permissionNamed(b *PermissionBase, grantable, objectName string) Params {
	o := b.options()
	o["grantables"] = []string{grantable}
	o["object_name"] = objectName
	return o
}

// ---------------------------------------------------------------------------
// Datasource

// DatasourcePermission grants database privileges on a datasource object
// path ("ds"."db"."schema"."object", where "*" means all).
type DatasourcePermission struct {
	PermissionBase
	// Permissions are the privileges to grant.
	Permissions []DBPermission
	// Datasource, Database, Schema and Object form the object path. "*"
	// matches everything; empty parts are omitted.
	Datasource string
	Database   string
	Schema     string
	Object     string
	// Where is an optional row filter clause (without WHERE).
	Where string
	// RowLimit limits the rows returned: a number, "none" for unlimited, or
	// empty for the server default.
	RowLimit string
}

// NewDatasourcePermission returns a permission granting perms to grantee.
// Set the object path with [DatasourcePermission.On].
func NewDatasourcePermission(grantee string, perms ...DBPermission) *DatasourcePermission {
	return &DatasourcePermission{PermissionBase: PermissionBase{Grantee: grantee}, Permissions: perms}
}

// On sets the database object path. Pass "*" for all, or "" to omit a level.
func (p *DatasourcePermission) On(datasource, database, schema, object string) *DatasourcePermission {
	p.Datasource, p.Database, p.Schema, p.Object = datasource, database, schema, object
	return p
}

// WithUnlimitedRows allows the grantee to see all rows.
func (p *DatasourcePermission) WithUnlimitedRows() *DatasourcePermission {
	p.RowLimit = "none"
	return p
}

// WithRowLimit limits the number of rows returned.
func (p *DatasourcePermission) WithRowLimit(limit int) *DatasourcePermission {
	p.RowLimit = strconv.Itoa(limit)
	return p
}

func datasourceQuoteName(val string) string {
	if val == "*" {
		return "*"
	}
	if val != "" {
		return permissionQuote(val)
	}
	return ""
}

// GrantOptions implements [Permission].
func (p *DatasourcePermission) GrantOptions() Params {
	o := p.options()
	g := make([]string, 0, len(p.Permissions))
	for _, x := range p.Permissions {
		g = append(g, string(x))
	}
	o["grantables"] = g
	if p.Where != "" {
		o["where_clause"] = p.Where
	}
	if p.RowLimit != "" {
		o["limit"] = p.RowLimit
	}
	var parts []string
	for _, v := range []string{p.Datasource, p.Database, p.Schema, p.Object} {
		if q := datasourceQuoteName(v); q != "" {
			parts = append(parts, q)
		}
	}
	o["object_name"] = strings.Join(parts, ".")
	return o
}

// ---------------------------------------------------------------------------
// Policy

// PolicyPermission grants a policy.
type PolicyPermission struct {
	PermissionBase
	// Name is the policy name.
	Name string
}

// NewPolicyPermission returns a permission granting policyName to grantee.
func NewPolicyPermission(policyName, grantee string) *PolicyPermission {
	return &PolicyPermission{PermissionBase: PermissionBase{Grantee: grantee}, Name: policyName}
}

// GrantOptions implements [Permission].
func (p *PolicyPermission) GrantOptions() Params {
	o := p.options()
	if p.Name == "" {
		o["grantables"] = []string{}
	} else {
		o["grantables"] = []string{` POLICY "` + p.Name + `"`}
	}
	return o
}

// ---------------------------------------------------------------------------
// Encryption key

// KeyPermission grants KEY USAGE on an encryption key.
type KeyPermission struct {
	PermissionBase
	// Name is the encryption key name.
	Name string
}

// NewKeyPermission returns a permission granting usage of keyName to grantee.
func NewKeyPermission(keyName, grantee string) *KeyPermission {
	return &KeyPermission{PermissionBase: PermissionBase{Grantee: grantee}, Name: keyName}
}

// GrantOptions implements [Permission].
func (p *KeyPermission) GrantOptions() Params {
	o := p.options()
	if p.Name == "" {
		o["grantables"] = []string{}
	} else {
		o["grantables"] = []string{"KEY USAGE"}
	}
	o["object_name"] = p.Name
	return o
}

// ---------------------------------------------------------------------------
// Role

// RolePermission grants a role.
type RolePermission struct {
	PermissionBase
	// Name is the role name.
	Name string
}

// NewRolePermission returns a permission granting roleName to grantee.
func NewRolePermission(roleName, grantee string) *RolePermission {
	return &RolePermission{PermissionBase: PermissionBase{Grantee: grantee}, Name: roleName}
}

// GrantOptions implements [Permission].
func (p *RolePermission) GrantOptions() Params {
	o := p.options()
	o["grantables"] = permissionGrantables(p.Name)
	return o
}

// ---------------------------------------------------------------------------
// SSH / SFTP / RDP

// SSHLoginPermission grants SSH on an SSH login.
type SSHLoginPermission struct {
	PermissionBase
	// Name is the SSH login name.
	Name string
}

// NewSSHLoginPermission returns a permission granting SSH on loginName to grantee.
func NewSSHLoginPermission(loginName, grantee string) *SSHLoginPermission {
	return &SSHLoginPermission{PermissionBase: PermissionBase{Grantee: grantee}, Name: loginName}
}

// GrantOptions implements [Permission].
func (p *SSHLoginPermission) GrantOptions() Params {
	return permissionNamed(&p.PermissionBase, "SSH", p.Name)
}

// SFTPLoginPermission grants SFTP on an SSH login.
type SFTPLoginPermission struct {
	PermissionBase
	// Name is the SSH login name.
	Name string
}

// NewSFTPLoginPermission returns a permission granting SFTP on loginName to grantee.
func NewSFTPLoginPermission(loginName, grantee string) *SFTPLoginPermission {
	return &SFTPLoginPermission{PermissionBase: PermissionBase{Grantee: grantee}, Name: loginName}
}

// GrantOptions implements [Permission].
func (p *SFTPLoginPermission) GrantOptions() Params {
	return permissionNamed(&p.PermissionBase, "SFTP", p.Name)
}

// RemoteDesktopLoginPermission grants RDP on a remote desktop login.
type RemoteDesktopLoginPermission struct {
	PermissionBase
	// Name is the remote desktop login name.
	Name string
}

// NewRemoteDesktopLoginPermission returns a permission granting RDP on
// loginName to grantee.
func NewRemoteDesktopLoginPermission(loginName, grantee string) *RemoteDesktopLoginPermission {
	return &RemoteDesktopLoginPermission{PermissionBase: PermissionBase{Grantee: grantee}, Name: loginName}
}

// GrantOptions implements [Permission].
func (p *RemoteDesktopLoginPermission) GrantOptions() Params {
	return permissionNamed(&p.PermissionBase, "RDP", p.Name)
}

// ---------------------------------------------------------------------------
// IP resource

// IPResourcePermission grants IP USAGE (or UNAUTHENTICATED IP USAGE) on an IP
// resource.
type IPResourcePermission struct {
	PermissionBase
	// Name is the IP resource name.
	Name string
	// Unauthenticated grants UNAUTHENTICATED IP USAGE, i.e. access without
	// always requiring 2FA (TS always2FA(false)). The default grants IP USAGE.
	Unauthenticated bool
}

// NewIPResourcePermission returns a permission granting IP USAGE on
// resourceName to grantee.
func NewIPResourcePermission(resourceName, grantee string) *IPResourcePermission {
	return &IPResourcePermission{PermissionBase: PermissionBase{Grantee: grantee}, Name: resourceName}
}

// GrantOptions implements [Permission].
func (p *IPResourcePermission) GrantOptions() Params {
	g := "IP USAGE"
	if p.Unauthenticated {
		g = "UNAUTHENTICATED IP USAGE"
	}
	return permissionNamed(&p.PermissionBase, g, permissionQuote(p.Name))
}

// ---------------------------------------------------------------------------
// Mamori server privileges

// MamoriPermission grants mamori server privileges.
type MamoriPermission struct {
	PermissionBase
	// Permissions are the privileges to grant.
	Permissions []MamoriPrivilege
}

// NewMamoriPermission returns a permission granting perms to grantee.
func NewMamoriPermission(grantee string, perms ...MamoriPrivilege) *MamoriPermission {
	return &MamoriPermission{PermissionBase: PermissionBase{Grantee: grantee}, Permissions: perms}
}

// GrantOptions implements [Permission].
func (p *MamoriPermission) GrantOptions() Params {
	o := p.options()
	g := make([]string, 0, len(p.Permissions))
	for _, x := range p.Permissions {
		g = append(g, string(x))
	}
	o["grantables"] = g
	return o
}

// ---------------------------------------------------------------------------
// Secret / HTTP resource / script / script flow

// SecretPermission grants REVEAL SECRET on a secret.
type SecretPermission struct {
	PermissionBase
	// Name is the secret name.
	Name string
}

// NewSecretPermission returns a permission granting REVEAL SECRET on
// secretName to grantee.
func NewSecretPermission(secretName, grantee string) *SecretPermission {
	return &SecretPermission{PermissionBase: PermissionBase{Grantee: grantee}, Name: secretName}
}

// GrantOptions implements [Permission].
func (p *SecretPermission) GrantOptions() Params {
	return permissionNamed(&p.PermissionBase, "REVEAL SECRET", permissionQuote(p.Name))
}

// HTTPResourcePermission grants HTTP ACCESS on an HTTP resource.
type HTTPResourcePermission struct {
	PermissionBase
	// Name is the HTTP resource name.
	Name string
}

// NewHTTPResourcePermission returns a permission granting HTTP ACCESS on
// resourceName to grantee.
func NewHTTPResourcePermission(resourceName, grantee string) *HTTPResourcePermission {
	return &HTTPResourcePermission{PermissionBase: PermissionBase{Grantee: grantee}, Name: resourceName}
}

// GrantOptions implements [Permission].
func (p *HTTPResourcePermission) GrantOptions() Params {
	return permissionNamed(&p.PermissionBase, "HTTP ACCESS", permissionQuote(p.Name))
}

// ScriptPermission grants EXECUTE SCRIPT on a script.
type ScriptPermission struct {
	PermissionBase
	// Name is the script name.
	Name string
}

// NewScriptPermission returns a permission granting EXECUTE SCRIPT on
// scriptName to grantee.
func NewScriptPermission(scriptName, grantee string) *ScriptPermission {
	return &ScriptPermission{PermissionBase: PermissionBase{Grantee: grantee}, Name: scriptName}
}

// GrantOptions implements [Permission].
func (p *ScriptPermission) GrantOptions() Params {
	return permissionNamed(&p.PermissionBase, "EXECUTE SCRIPT", permissionQuote(p.Name))
}

// ScriptFlowPermission grants EXECUTE SCRIPT FLOW on a script flow.
type ScriptFlowPermission struct {
	PermissionBase
	// Name is the script flow name.
	Name string
}

// NewScriptFlowPermission returns a permission granting EXECUTE SCRIPT FLOW
// on flowName to grantee.
func NewScriptFlowPermission(flowName, grantee string) *ScriptFlowPermission {
	return &ScriptFlowPermission{PermissionBase: PermissionBase{Grantee: grantee}, Name: flowName}
}

// GrantOptions implements [Permission].
func (p *ScriptFlowPermission) GrantOptions() Params {
	return permissionNamed(&p.PermissionBase, "EXECUTE SCRIPT FLOW", permissionQuote(p.Name))
}

// ---------------------------------------------------------------------------
// Credential

// CredentialPermission grants CREDENTIAL USAGE on a datasource credential.
type CredentialPermission struct {
	PermissionBase
	// Datasource is the datasource the credential belongs to.
	Datasource string
	// LoginName is the database login. When empty the grant applies to the
	// datasource as a whole.
	LoginName string
}

// NewCredentialPermission returns a CREDENTIAL USAGE permission for grantee;
// set Datasource and LoginName afterwards.
func NewCredentialPermission(grantee string) *CredentialPermission {
	return &CredentialPermission{PermissionBase: PermissionBase{Grantee: grantee}}
}

// GrantOptions implements [Permission].
func (p *CredentialPermission) GrantOptions() Params {
	name := p.Datasource
	if p.LoginName != "" {
		name = permissionQuote(p.LoginName + "@" + p.Datasource)
	}
	return permissionNamed(&p.PermissionBase, "CREDENTIAL USAGE", name)
}

// ---------------------------------------------------------------------------
// Factories

// NewPermission returns an empty permission of type t (TS Permissions.make).
// PermissionTypeSSH yields an *SSHLoginPermission.
func NewPermission(t PermissionType) (Permission, error) {
	switch t {
	case PermissionTypeDatasource:
		return &DatasourcePermission{}, nil
	case PermissionTypeIPResource:
		return &IPResourcePermission{}, nil
	case PermissionTypeKey:
		return &KeyPermission{}, nil
	case PermissionTypeMamori:
		return &MamoriPermission{}, nil
	case PermissionTypePolicy:
		return &PolicyPermission{}, nil
	case PermissionTypeRemoteDesktop:
		return &RemoteDesktopLoginPermission{}, nil
	case PermissionTypeRole:
		return &RolePermission{}, nil
	case PermissionTypeSSH:
		return &SSHLoginPermission{}, nil
	case PermissionTypeHTTPResource:
		return &HTTPResourcePermission{}, nil
	case PermissionTypeSecret:
		return &SecretPermission{}, nil
	case PermissionTypeCredential:
		return &CredentialPermission{}, nil
	case PermissionTypeScript:
		return &ScriptPermission{}, nil
	case PermissionTypeScriptFlow:
		return &ScriptFlowPermission{}, nil
	}
	return nil, fmt.Errorf("mamori: unknown permission type %q", t)
}

// permissionRecordString returns rec[key] if it is a non-empty string.
func permissionRecordString(rec Params, key string) (string, bool) {
	s, ok := rec[key].(string)
	return s, ok && s != ""
}

// PermissionFromRecord converts a granted permission record (as returned by
// [PermissionService.List]) into its concrete [Permission] type, chosen by
// the record's "permissiontype" (TS Permissions.factory). The grantee comes
// from "grantee" and the object name from "key_name". An unknown
// permissiontype returns an error.
func PermissionFromRecord(rec Params) (Permission, error) {
	ptype, _ := rec["permissiontype"].(string)
	keyName, _ := permissionRecordString(rec, "key_name")

	var p Permission
	switch ptype {
	case "SSH":
		p = &SSHLoginPermission{Name: keyName}
	case "SFTP":
		p = &SFTPLoginPermission{Name: keyName}
	case "IP USAGE":
		p = &IPResourcePermission{Name: keyName}
	case "UNAUTHENTICATED IP USAGE":
		p = &IPResourcePermission{Name: keyName, Unauthenticated: true}
	case "RDP":
		p = &RemoteDesktopLoginPermission{Name: keyName}
	case "KEY USAGE":
		p = &KeyPermission{Name: keyName}
	case "CREDENTIAL USAGE":
		c := &CredentialPermission{LoginName: keyName}
		if s, ok := permissionRecordString(rec, "onsystem"); ok {
			c.Datasource = s
		}
		if s, ok := permissionRecordString(rec, "loginName"); ok {
			c.LoginName = s
		}
		if s, ok := permissionRecordString(rec, "datasource"); ok {
			c.Datasource = s
		}
		p = c
	case "REVEAL SECRET":
		p = &SecretPermission{Name: keyName}
	case "HTTP ACCESS":
		p = &HTTPResourcePermission{Name: keyName}
	case "EXECUTE SCRIPT":
		p = &ScriptPermission{Name: keyName}
	case "EXECUTE SCRIPT FLOW":
		p = &ScriptFlowPermission{Name: keyName}
	default:
		for _, d := range dbPermissions {
			if string(d) == ptype {
				p = datasourcePermissionFromRecord(rec, d)
				break
			}
		}
		if p == nil {
			for _, m := range mamoriPrivileges {
				if string(m) == ptype {
					p = &MamoriPermission{Permissions: []MamoriPrivilege{m}}
					break
				}
			}
		}
	}
	if p == nil {
		return nil, fmt.Errorf("mamori: unknown permission type %q", ptype)
	}
	p.Base().applyRecord(rec)
	return p, nil
}

func datasourcePermissionFromRecord(rec Params, perm DBPermission) *DatasourcePermission {
	d := &DatasourcePermission{Permissions: []DBPermission{perm}}
	if s, ok := permissionRecordString(rec, "permissions"); ok {
		d.Permissions = nil
		for _, x := range strings.Split(s, ",") {
			d.Permissions = append(d.Permissions, DBPermission(x))
		}
	}
	for key, dst := range map[string]*string{
		"datasource": &d.Datasource,
		"database":   &d.Database,
		"schema":     &d.Schema,
		"object":     &d.Object,
		"where":      &d.Where,
		"rowLimit":   &d.RowLimit,
	} {
		if s, ok := permissionRecordString(rec, key); ok {
			*dst = s
		}
	}
	return d
}
