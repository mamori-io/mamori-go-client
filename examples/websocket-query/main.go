// Command websocket-query streams the rows of a query over the websocket
// interface, fetching batches as needed.
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
	ws, err := mamori.DialWebsocket(ctx, mamori.WebsocketURL(c.BaseURL()), user, password,
		&mamori.WSOptions{HTTPClient: c.HTTPClient()})
	if err != nil {
		log.Fatal(err)
	}
	defer ws.Close()

	n := 0
	for row, err := range ws.Select(ctx, "select * from SYS.QUERIES", nil) {
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(row)
		n++
	}
	fmt.Printf("fetched %d rows\n", n)
}
