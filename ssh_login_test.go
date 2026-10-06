package mamori

import (
	"context"
	"encoding/json"
	"testing"
)

func TestSSHLoginSQL(t *testing.T) {
	c, reqs := newTestClient(t, func(r recordedRequest) any {
		return []Params{{"status": "ok"}}
	})
	ctx := context.Background()
	l := NewSSHLogin("lo'gin")
	l.Host, l.Port = "localhost", 22
	l.User, l.PrivateKeyName = "root", "key1"
	row, err := c.SSHLogins.Create(ctx, l)
	if err != nil || row["status"] != "ok" {
		t.Fatalf("row=%v err=%v", row, err)
	}
	want := "CALL ADD_SSH_LOGIN('lo''gin', 'ssh://root@localhost', 'key1', '','', '30')"
	if got := (*reqs)[0].Body["sql"]; got != want {
		t.Fatalf("sql = %v\nwant  %v", got, want)
	}

	l2 := NewSSHLogin("n")
	l2.ID = "5"
	l2.Host, l2.Port, l2.Password, l2.ThemeName, l2.IdleTimeout = "h", 2200, "pw", "dark", 10
	if _, err := c.SSHLogins.Update(ctx, l2); err != nil {
		t.Fatal(err)
	}
	want = "call update_ssh_login(5, 'n', 'ssh://h:2200', null, 'pw', 'dark', '10')"
	if got := (*reqs)[1].Body["sql"]; got != want {
		t.Fatalf("sql = %v\nwant  %v", got, want)
	}

	if _, err := c.SSHLogins.Delete(ctx, "n"); err != nil {
		t.Fatal(err)
	}
	if got := (*reqs)[2].Body["sql"]; got != "CALL DELETE_SSH_LOGIN('n')" {
		t.Fatalf("sql = %v", got)
	}
	if _, err := c.SSHLogins.GetAll(ctx); err != nil {
		t.Fatal(err)
	}
	if got := (*reqs)[3].Body["sql"]; got != "call ssh_logins()" {
		t.Fatalf("sql = %v", got)
	}
}

func TestSSHLoginDecodeURI(t *testing.T) {
	var l SSHLogin
	if err := json.Unmarshal([]byte(`{"id":3,"name":"n","uri":"ssh://bob@host:2222","private_key_name":"k"}`), &l); err != nil {
		t.Fatal(err)
	}
	if l.ID != "3" || l.User != "bob" || l.Host != "host" || l.Port != 2222 || l.PrivateKeyName != "k" {
		t.Fatalf("%+v", l)
	}
	if err := json.Unmarshal([]byte(`{"uri":"ssh://other"}`), &l); err != nil {
		t.Fatal(err)
	}
	if l.User != "" || l.Host != "other" || l.Port != 22 {
		t.Fatalf("%+v", l)
	}
}
