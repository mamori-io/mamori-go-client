package mamori

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/coder/websocket"
)

// WSClient is a client for the mamori websocket query interface
// (/websockets/query). Create one with [DialWebsocket] or
// [Client.WebsocketLogin]. It is safe for concurrent use.
type WSClient struct {
	conn      *websocket.Conn
	authtoken string
	nextID    atomic.Int64

	mu       sync.Mutex
	pending  map[int64]*wsPending
	closed   bool
	closeErr error
	done     chan struct{}
}

type wsPending struct {
	ch     chan *WSResponse
	stream bool
	gone   chan struct{} // closed when the requester stops listening
	once   sync.Once
}

// WSOptions configures [DialWebsocket].
type WSOptions struct {
	// HTTPClient is used for the websocket handshake. Use the HTTP client of
	// a [Client] created with WithInsecureSkipVerify to accept self-signed
	// certificates.
	HTTPClient *http.Client
	// AuthToken, if set, skips the authenticate command and uses this token.
	AuthToken string
	// AuthOptions are additional options sent with the authenticate command.
	AuthOptions Params
}

// WSColumn describes a result column.
type WSColumn struct {
	Name string `json:"name"`
	Type string `json:"type,omitempty"`
}

// WSResponse is a message received from the websocket server.
type WSResponse struct {
	Task struct {
		ID        flexInt `json:"id"`
		AuthToken string  `json:"authtoken,omitempty"`
	} `json:"task"`
	Error    any        `json:"error,omitempty"`
	Complete bool       `json:"complete,omitempty"`
	Meta     []WSColumn `json:"meta,omitempty"`
	Rows     [][]any    `json:"rows,omitempty"`

	// Raw is the complete undecoded message.
	Raw json.RawMessage `json:"-"`
}

// WSError is returned when the server responds to a request with an error.
type WSError struct {
	Response *WSResponse
}

func (e *WSError) Error() string {
	switch v := e.Response.Error.(type) {
	case string:
		return "mamori: websocket: " + v
	case map[string]any:
		if m, ok := v["message"].(string); ok {
			return "mamori: websocket: " + m
		}
	}
	return "mamori: websocket: " + string(e.Response.Raw)
}

// ErrWSClosed is returned for requests on a closed websocket.
var ErrWSClosed = errors.New("mamori: websocket closed")

// flexInt decodes a JSON number or numeric string.
type flexInt int64

func (f *flexInt) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		*f = 0
		return nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return err
	}
	*f = flexInt(n)
	return nil
}

var httpScheme = regexp.MustCompile(`^http`)

// WebsocketURL converts an http(s) base URL to the ws(s) query endpoint.
func WebsocketURL(base string) string {
	return httpScheme.ReplaceAllString(strings.TrimRight(base, "/"), "ws") + "/websockets/query"
}

// DialWebsocket connects to the websocket query endpoint at url (see
// [WebsocketURL]) and authenticates as username/password.
func DialWebsocket(ctx context.Context, url, username, password string, opts *WSOptions) (*WSClient, error) {
	if opts == nil {
		opts = &WSOptions{}
	}
	conn, _, err := websocket.Dial(ctx, url, &websocket.DialOptions{HTTPClient: opts.HTTPClient})
	if err != nil {
		return nil, fmt.Errorf("mamori: websocket dial: %w", err)
	}
	conn.SetReadLimit(-1)
	w := &WSClient{
		conn:      conn,
		authtoken: opts.AuthToken,
		pending:   map[int64]*wsPending{},
		done:      make(chan struct{}),
	}
	go w.readLoop()

	if w.authtoken == "" {
		authOpts := Params{}
		for k, v := range opts.AuthOptions {
			authOpts[k] = v
		}
		authOpts["user"] = username
		authOpts["password_encrypted"] = base64.StdEncoding.EncodeToString([]byte(password))
		resp, err := w.Send(ctx, Params{"command": "authenticate", "options": authOpts})
		if err != nil {
			w.Close()
			return nil, err
		}
		w.mu.Lock()
		w.authtoken = resp.Task.AuthToken
		w.mu.Unlock()
	}
	return w, nil
}

// WebsocketLogin opens a websocket query connection using the client's
// current session.
func (c *Client) WebsocketLogin(ctx context.Context) (*WSClient, error) {
	if !c.Authorized() {
		return nil, ErrNotLoggedIn
	}
	rows, err := c.Select(ctx, "call GENERATE_LOGIN_TOKEN()")
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, errors.New("mamori: GENERATE_LOGIN_TOKEN returned no rows")
	}
	token := fmt.Sprint(rows[0]["a1"])
	user, _ := c.Claims()["username"].(string)
	return DialWebsocket(ctx, WebsocketURL(c.BaseURL()), user, token, &WSOptions{HTTPClient: c.httpClient})
}

func (w *WSClient) readLoop() {
	ctx := context.Background()
	for {
		_, data, err := w.conn.Read(ctx)
		if err != nil {
			w.shutdown(err)
			return
		}
		var resp WSResponse
		if err := json.Unmarshal(data, &resp); err != nil {
			continue
		}
		resp.Raw = data
		id := int64(resp.Task.ID)

		w.mu.Lock()
		p := w.pending[id]
		if p != nil && (!p.stream || resp.Complete) {
			delete(w.pending, id)
		}
		w.mu.Unlock()
		if p == nil {
			continue
		}
		if p.stream {
			select {
			case p.ch <- &resp:
				if resp.Complete {
					close(p.ch)
				}
			case <-p.gone:
			}
		} else {
			p.ch <- &resp // buffered, single response
		}
	}
}

func (w *WSClient) shutdown(err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return
	}
	w.closed = true
	w.closeErr = err
	close(w.done)
	clear(w.pending)
}

// Close closes the connection. Pending requests fail with [ErrWSClosed].
func (w *WSClient) Close() error {
	err := w.conn.Close(websocket.StatusNormalClosure, "")
	w.shutdown(ErrWSClosed)
	return err
}

// Done is closed when the connection terminates.
func (w *WSClient) Done() <-chan struct{} { return w.done }

func (w *WSClient) register(req Params, stream bool) (int64, *wsPending, error) {
	var id int64
	switch v := req["id"].(type) {
	case int64:
		id = v
	case int:
		id = int64(v)
	default:
		id = w.nextID.Add(1)
		req["id"] = id
	}
	p := &wsPending{stream: stream, gone: make(chan struct{})}
	if stream {
		p.ch = make(chan *WSResponse, 16)
	} else {
		p.ch = make(chan *WSResponse, 1)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0, nil, ErrWSClosed
	}
	if w.authtoken != "" {
		req["authtoken"] = w.authtoken
	}
	w.pending[id] = p
	return id, p, nil
}

func (w *WSClient) unregister(id int64, p *wsPending) {
	w.mu.Lock()
	delete(w.pending, id)
	w.mu.Unlock()
	p.once.Do(func() { close(p.gone) })
}

func (w *WSClient) write(ctx context.Context, req Params) error {
	buf, err := json.Marshal(req)
	if err != nil {
		return err
	}
	return w.conn.Write(ctx, websocket.MessageText, buf)
}

// Send sends a raw request and waits for its response. An "id" is assigned
// if req has none. A response carrying an error is returned as [*WSError].
func (w *WSClient) Send(ctx context.Context, req Params) (*WSResponse, error) {
	id, p, err := w.register(req, false)
	if err != nil {
		return nil, err
	}
	if err := w.write(ctx, req); err != nil {
		w.unregister(id, p)
		return nil, err
	}
	select {
	case resp := <-p.ch:
		if resp.Error != nil && resp.Error != false {
			return resp, &WSError{Response: resp}
		}
		return resp, nil
	case <-w.done:
		return nil, w.closeErr
	case <-ctx.Done():
		w.unregister(id, p)
		return nil, ctx.Err()
	}
}

func optionsOrEmpty(o Params) Params {
	if o == nil {
		return Params{}
	}
	return o
}

// Query runs a SQL statement and returns the first batch of results.
func (w *WSClient) Query(ctx context.Context, sql string, options Params) (*WSResponse, error) {
	return w.Send(ctx, Params{"command": "query", "statement": sql, "options": optionsOrEmpty(options)})
}

// WebSQL runs a statement through the web SQL interface.
func (w *WSClient) WebSQL(ctx context.Context, sql string, options Params) (*WSResponse, error) {
	return w.Send(ctx, Params{"command": "websql", "statement": sql, "options": optionsOrEmpty(options)})
}

// WebSQLConfig fetches the web SQL configuration.
func (w *WSClient) WebSQLConfig(ctx context.Context, options Params) (*WSResponse, error) {
	return w.Send(ctx, Params{"command": "websql_config", "options": optionsOrEmpty(options)})
}

// Execute executes a statement.
func (w *WSClient) Execute(ctx context.Context, sql string, options Params) (*WSResponse, error) {
	return w.Send(ctx, Params{"command": "execute", "statement": sql, "options": optionsOrEmpty(options)})
}

// Next fetches the next batch of rows for task id.
func (w *WSClient) Next(ctx context.Context, id int64) (*WSResponse, error) {
	return w.Send(ctx, Params{"command": "next", "id": id})
}

// Cancel cancels task id.
func (w *WSClient) Cancel(ctx context.Context, id int64) (*WSResponse, error) {
	return w.Send(ctx, Params{"command": "cancel", "id": id})
}

// QueryRows runs a query and returns the first batch as rows keyed by
// lower-cased column name.
func (w *WSClient) QueryRows(ctx context.Context, sql string, options Params) ([]Row, error) {
	resp, err := w.Query(ctx, sql, options)
	if err != nil {
		return nil, err
	}
	return resp.rowMaps(true), nil
}

func (r *WSResponse) rowMaps(lower bool) []Row {
	cols := make([]string, len(r.Meta))
	for i, c := range r.Meta {
		cols[i] = c.Name
		if lower {
			cols[i] = strings.ToLower(c.Name)
		}
	}
	rows := make([]Row, 0, len(r.Rows))
	for _, data := range r.Rows {
		row := make(Row, len(cols))
		for i, c := range cols {
			if i < len(data) {
				row[c] = data[i]
			}
		}
		rows = append(rows, row)
	}
	return rows
}

// Select runs a query and iterates over every result row, fetching further
// batches as needed. Iteration stops at the first error, which is yielded
// with a nil row.
//
//	for row, err := range ws.Select(ctx, "select * from SYS.QUERIES", nil) {
//		if err != nil { return err }
//		fmt.Println(row)
//	}
func (w *WSClient) Select(ctx context.Context, sql string, options Params) iter.Seq2[Row, error] {
	return func(yield func(Row, error) bool) {
		resp, err := w.Query(ctx, sql, options)
		if err != nil {
			yield(nil, err)
			return
		}
		cols := make([]string, len(resp.Meta))
		for i, c := range resp.Meta {
			cols[i] = c.Name
		}
		taskID := int64(resp.Task.ID)
		for {
			for _, data := range resp.Rows {
				row := make(Row, len(cols))
				for i, c := range cols {
					if i < len(data) {
						row[c] = data[i]
					}
				}
				if !yield(row, nil) {
					return
				}
			}
			if resp.Complete || len(resp.Rows) == 0 {
				return
			}
			if resp, err = w.Next(ctx, taskID); err != nil {
				yield(nil, err)
				return
			}
		}
	}
}

// Tail subscribes to a server logger. Messages are delivered on the returned
// channel until the stream completes, the connection closes, or ctx is
// cancelled.
func (w *WSClient) Tail(ctx context.Context, logger string) (<-chan *WSResponse, error) {
	req := Params{"command": "tail", "logger": logger}
	id, p, err := w.register(req, true)
	if err != nil {
		return nil, err
	}
	if err := w.write(ctx, req); err != nil {
		w.unregister(id, p)
		return nil, err
	}
	out := make(chan *WSResponse)
	go func() {
		defer close(out)
		defer w.unregister(id, p)
		for {
			select {
			case resp, ok := <-p.ch:
				if !ok {
					return
				}
				select {
				case out <- resp:
				case <-ctx.Done():
					return
				case <-w.done:
					return
				}
			case <-ctx.Done():
				return
			case <-w.done:
				return
			}
		}
	}()
	return out, nil
}
