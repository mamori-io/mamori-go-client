// Command secret creates a secret, grants it to a user, reveals it and
// deletes it again.
package main

import (
	"fmt"
	"log"

	mamori "mamori.io/mamori-go-client"
	"mamori.io/mamori-go-client/examples/internal/setup"
)

func main() {
	ctx, cancel, c := setup.Client()
	defer cancel()
	_, user, password := setup.Env()
	if _, err := c.Login(ctx, user, password); err != nil {
		log.Fatal(err)
	}
	defer c.Logout(ctx)

	s := mamori.NewSecret(mamori.SecretProtocolSSH, mamori.AddUniqueExtension("example_secret"))
	s.Username = "root"
	s.Hostname = "10.0.0.1"
	s.Secret = "hunter2"
	if _, err := c.Secrets.Create(ctx, s); err != nil {
		log.Fatal(err)
	}
	defer c.Secrets.DeleteByName(ctx, s.Name)

	if err := c.Secrets.GrantTo(ctx, s.Name, "alice"); err != nil {
		log.Fatal(err)
	}

	got, err := c.Secrets.GetByName(ctx, s.Name)
	if err != nil {
		log.Fatal(err)
	}
	revealed, err := c.Secrets.Reveal(ctx, got.ID)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("secret %s (id %s): %s\n", got.Name, got.ID, revealed)
}
