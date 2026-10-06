package mamori

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

// Datasource is a target database configured in mamori.
//
// Example:
//
//	ds := mamori.NewDatasource("test")
//	ds.Type, ds.Driver = "POSTGRESQL", "postgres"
//	ds.At("10.0.2.2", "5432").WithDatabase("mamori")
//	ds.User, ds.Password = "postgres", "postgres"
//	ds.URLProperties = "allowEncodingChanges=true;defaultNchar=true"
//	_, err := client.Datasources.Create(ctx, ds)
type Datasource struct {
	// Name is the unique datasource name.
	Name string `json:"name"`
	// Type is the datasource type, e.g. ORACLE, POSTGRESQL, SQL_SERVER.
	Type string `json:"type,omitempty"`
	// Driver is the name of the configured database driver.
	Driver string `json:"driver,omitempty"`
	// Host is the host name or IP address of the database.
	Host string `json:"host,omitempty"`
	// Port is the listening port of the database.
	Port string `json:"port,omitempty"`
	// Group is an optional datasource group.
	Group string `json:"group,omitempty"`
	// User is the database user mamori connects as.
	User string `json:"user,omitempty"`
	// Password is User's password.
	Password string `json:"password,omitempty"`
	// TempDatabase is the database used for temporary tables. It defaults
	// to Database.
	TempDatabase string `json:"tempDatabase,omitempty"`
	// Database is the default database.
	Database string `json:"database,omitempty"`
	// CaseSensitive marks object names as case sensitive.
	CaseSensitive bool `json:"caseSensitive,omitempty"`
	// Enabled enables or disables the datasource; nil leaves the default.
	Enabled *bool `json:"enabled,omitempty"`
	// URLProperties are extra properties added to the JDBC URL.
	URLProperties string `json:"urlProperties,omitempty"`
	// ExtraOptions are additional comma separated options in SQL syntax,
	// e.g. "POOL_MAXIMUM '3', ENABLED FALSE".
	ExtraOptions string `json:"extraOptions,omitempty"`
	// CredentialResetDays enables managed passwords, reset every n days.
	CredentialResetDays string `json:"credential_reset_days,omitempty"`
	// CredentialRole is the role used for managed password resets.
	CredentialRole string `json:"credential_role,omitempty"`
	// ConnectionString is a full connection string, used instead of
	// Host/Port/Database.
	ConnectionString string `json:"connection_string,omitempty"`
	// WebSQLAutoCommitDefault is the default auto-commit for WebSQL
	// sessions. When nil, Oracle defaults to false and other types to true.
	WebSQLAutoCommitDefault *bool `json:"webSqlAutoCommitDefault,omitempty"`
}

// NewDatasource returns a datasource with the given name.
func NewDatasource(name string) *Datasource {
	return &Datasource{Name: name}
}

// At sets the address of the database and clears any connection string.
func (d *Datasource) At(host, port string) *Datasource {
	d.Host = host
	d.Port = port
	d.ConnectionString = ""
	return d
}

// WithDatabase sets the default database. TempDatabase is set to the same
// value unless it was already set.
func (d *Datasource) WithDatabase(database string) *Datasource {
	d.Database = database
	if d.TempDatabase == "" {
		d.TempDatabase = database
	}
	return d
}

// WithConnectionString sets a full connection string and clears the host,
// port and database.
func (d *Datasource) WithConnectionString(cs string) *Datasource {
	d.ConnectionString = cs
	d.Host = ""
	d.Port = ""
	d.WithDatabase("")
	return d
}

// DatasourceUpdate lists the datasource properties to change in
// [DatasourceService.Update]. nil fields are left unchanged. As in the
// TypeScript SDK, empty strings and a false CaseSensitive produce no option.
type DatasourceUpdate struct {
	Host                    *string
	Driver                  *string
	User                    *string
	Password                *string
	CredentialResetDays     *string
	CredentialRole          *string
	Port                    *string
	TempDatabase            *string
	Database                *string
	CaseSensitive           *bool
	WebSQLAutoCommitDefault *bool
	Enabled                 *bool
	Group                   *string
	URLProperties           *string
	ConnectionString        *string
	ExtraOptions            *string
}

// datasourceOptions builds the option list sent when creating or altering
// a datasource. Quoted values have single quotes escaped; ExtraOptions is
// passed through verbatim, and like the TypeScript SDK the joined list is
// split on commas (so ExtraOptions may hold several options).
func datasourceOptions(d *Datasource, update bool) []string {
	var res []string
	q := sqlQuote
	tf := func(b bool) string {
		if b {
			return "'TRUE'"
		}
		return "'FALSE'"
	}
	if update && d.Host != "" {
		res = append(res, "HOST "+q(d.Host))
	}
	if d.Driver != "" {
		res = append(res, "DRIVER "+q(d.Driver))
	}
	if d.User != "" {
		res = append(res, "USER "+q(d.User))
	}
	if d.Password != "" {
		res = append(res, "PASSWORD "+q(d.Password))
	}
	if d.CredentialResetDays != "" {
		res = append(res, CredentialResetDays+" "+q(d.CredentialResetDays))
	}
	if d.CredentialRole != "" {
		res = append(res, CredentialRole+" "+q(d.CredentialRole))
	}
	if d.Port != "" {
		res = append(res, "PORT "+q(d.Port))
	}
	if d.TempDatabase != "" {
		res = append(res, "TEMPDATABASE "+q(d.TempDatabase))
	} else if d.Database != "" {
		res = append(res, "TEMPDATABASE "+q(d.Database))
	}
	if d.Database != "" {
		res = append(res, "DEFAULTDATABASE "+q(d.Database))
	}
	if d.CaseSensitive {
		res = append(res, "OBJECTNAMECASESENSITIVE 'TRUE'")
	}
	if d.WebSQLAutoCommitDefault != nil {
		res = append(res, "WEBSQLAUTOCOMMITDEFAULT "+tf(*d.WebSQLAutoCommitDefault))
	}
	if d.Enabled != nil {
		res = append(res, "ENABLED "+tf(*d.Enabled))
	}
	if d.Group != "" {
		res = append(res, "DATASOURCE GROUP "+q(d.Group))
	}
	if d.URLProperties != "" {
		res = append(res, "CONNECTION_PROPERTIES "+q(d.URLProperties))
	}
	if d.ConnectionString != "" {
		res = append(res, "CONNECTION_STRING "+q(d.ConnectionString))
	}
	r := strings.Join(res, ",")
	if d.ExtraOptions != "" {
		r += "," + d.ExtraOptions
	}
	return strings.Split(r, ",")
}

// datasourceUpdateOptions applies the requested changes to an empty
// datasource (only differing values when diffsOnly) and builds the options.
func datasourceUpdateOptions(cur *Datasource, u DatasourceUpdate, diffsOnly bool) []string {
	var o Datasource
	str := func(dst *string, v *string, curv string) {
		if v != nil && (!diffsOnly || *v != curv) {
			*dst = *v
		}
	}
	str(&o.Host, u.Host, cur.Host)
	str(&o.Driver, u.Driver, cur.Driver)
	str(&o.User, u.User, cur.User)
	str(&o.Password, u.Password, cur.Password)
	str(&o.CredentialResetDays, u.CredentialResetDays, cur.CredentialResetDays)
	str(&o.CredentialRole, u.CredentialRole, cur.CredentialRole)
	str(&o.Port, u.Port, cur.Port)
	str(&o.TempDatabase, u.TempDatabase, cur.TempDatabase)
	str(&o.Database, u.Database, cur.Database)
	str(&o.Group, u.Group, cur.Group)
	str(&o.URLProperties, u.URLProperties, cur.URLProperties)
	str(&o.ConnectionString, u.ConnectionString, cur.ConnectionString)
	str(&o.ExtraOptions, u.ExtraOptions, cur.ExtraOptions)
	if u.CaseSensitive != nil && (!diffsOnly || *u.CaseSensitive != cur.CaseSensitive) {
		o.CaseSensitive = *u.CaseSensitive
	}
	optBool := func(v, curv *bool) *bool {
		if v == nil {
			return nil
		}
		if diffsOnly && curv != nil && *curv == *v {
			return nil
		}
		b := *v
		return &b
	}
	o.WebSQLAutoCommitDefault = optBool(u.WebSQLAutoCommitDefault, cur.WebSQLAutoCommitDefault)
	o.Enabled = optBool(u.Enabled, cur.Enabled)
	return datasourceOptions(&o, true)
}

// GetAll returns all the datasources the logged-in user has access to.
func (s *DatasourceService) GetAll(ctx context.Context) ([]Row, error) {
	raw, err := s.client.Call(ctx, http.MethodGet, "/v1/objects/databases?usersystems=true", nil)
	if err != nil {
		return nil, err
	}
	return decodeRows(raw)
}

// Read returns the datasource status record for name (including fields such
// as "available" and "status"), or ErrNotFound.
func (s *DatasourceService) Read(ctx context.Context, name string) (Row, error) {
	raw, err := s.client.Call(ctx, http.MethodGet, "/v1/objects/databases?usersystems=true&name="+pathEscape(name), nil)
	if err != nil {
		return nil, err
	}
	rows, err := decodeRows(raw)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, ErrNotFound
	}
	return rows[0], nil
}

// GetDrivers returns the configured database drivers.
func (s *DatasourceService) GetDrivers(ctx context.Context) (json.RawMessage, error) {
	return s.client.Call(ctx, http.MethodGet, "/v1/drivers", nil)
}

// GetTypes returns the supported datasource types.
func (s *DatasourceService) GetTypes(ctx context.Context) (json.RawMessage, error) {
	return s.client.Call(ctx, http.MethodGet, "/v1/driver_types", nil)
}

// Get returns the configuration of the named datasource, including its
// "options" list.
func (s *DatasourceService) Get(ctx context.Context, name string) (Params, error) {
	var out Params
	if err := s.client.CallInto(ctx, http.MethodGet, "/v1/systems/"+pathEscape(name), nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Create creates the datasource d.
func (s *DatasourceService) Create(ctx context.Context, d *Datasource) (json.RawMessage, error) {
	system := Params{"name": d.Name}
	if d.Type != "" {
		system["type"] = d.Type
	}
	if d.Host != "" {
		system["host"] = d.Host
	}
	return s.client.Call(ctx, http.MethodPost, "/v1/systems", Params{
		"preview":        "N",
		"system":         system,
		"options":        datasourceOptions(d, false),
		"authorizations": []any{},
	})
}

// Delete deletes the named datasource.
func (s *DatasourceService) Delete(ctx context.Context, name string) (json.RawMessage, error) {
	return s.client.Call(ctx, http.MethodDelete, "/v1/systems/"+pathEscape(name), nil)
}

// Update alters datasource d with the given changes. d supplies the name,
// type and current host; when diffsOnly is true only changes that differ
// from the values in d are sent.
func (s *DatasourceService) Update(ctx context.Context, d *Datasource, changes DatasourceUpdate, diffsOnly bool) (json.RawMessage, error) {
	system := Params{}
	if d.Type != "" {
		system["type"] = d.Type
	}
	// The TypeScript SDK sends the current host unless the update changes
	// it (in which case the HOST option carries the new value).
	if (changes.Host == nil || *changes.Host == "") && d.Host != "" {
		system["host"] = d.Host
	}
	return s.client.Call(ctx, http.MethodPut, "/v1/systems/"+pathEscape(d.Name), Params{
		"preview":        "N",
		"system":         system,
		"options":        datasourceUpdateOptions(d, changes, diffsOnly),
		"authorizations": []any{},
	})
}

func datasourceAuthPath(grantee string) string {
	return "/v1/grantee/" + pathEscape(strings.ToLower(grantee)) + "/datasource_authorization"
}

// AddCredential grants grantee (a user or role) a database credential for
// the datasource.
func (s *DatasourceService) AddCredential(ctx context.Context, datasource, grantee, dbUser, dbPassword string) (json.RawMessage, error) {
	return s.client.Call(ctx, http.MethodPost, datasourceAuthPath(grantee), Params{
		"datasource": datasource,
		"username":   dbUser,
		"password":   dbPassword,
	})
}

// AddCredentialWithManagedPassword grants grantee a database credential
// whose password is reset every resetDays days.
func (s *DatasourceService) AddCredentialWithManagedPassword(ctx context.Context, datasource, grantee, dbUser, dbPassword, resetDays string) (json.RawMessage, error) {
	return s.client.Call(ctx, http.MethodPost, datasourceAuthPath(grantee), Params{
		"datasource": datasource,
		"username":   dbUser,
		"password":   dbPassword,
		"reset_days": resetDays,
	})
}

// RemoveCredential removes grantee's credential for the datasource.
func (s *DatasourceService) RemoveCredential(ctx context.Context, datasource, grantee string) (json.RawMessage, error) {
	return s.client.Call(ctx, http.MethodDelete, datasourceAuthPath(grantee), Params{"datasource": datasource})
}

// ValidateCredential checks a database credential against the datasource.
// The server answers "Authorization valid" on success.
func (s *DatasourceService) ValidateCredential(ctx context.Context, datasource, grantee, dbUser, dbPassword string) (json.RawMessage, error) {
	return s.client.Call(ctx, http.MethodPost, datasourceAuthPath(grantee)+"/validate", Params{
		"datasource": datasource,
		"username":   dbUser,
		"password":   dbPassword,
	})
}
