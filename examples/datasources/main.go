// Command datasources logs in and lists the datasources visible to the user.
//
//	MAMORI_SERVER=https://mamori.example.com MAMORI_USERNAME=alice MAMORI_PASSWORD=... go run ./examples/datasources
package main

import (
	"fmt"
	"log"

	"mamori.io/mamori-go-client/examples/internal/setup"
)

func main() {
	ctx, cancel, c := setup.Client()
	defer cancel()
	_, user, password := setup.Env()
	login, err := c.Login(ctx, user, password)
	if err != nil {
		log.Fatal(err)
	}
	defer c.Logout(ctx)
	fmt.Printf("logged in as %s (roles %v)\n", login.Username, login.Roles)

	rows, err := c.Datasources.GetAll(ctx)
	if err != nil {
		log.Fatal(err)
	}
	for _, r := range rows {
		fmt.Println(r["name"], r["type"])
	}
}
