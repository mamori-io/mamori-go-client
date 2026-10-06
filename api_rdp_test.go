package mamori

import (
	"context"
	"net/http"
	"testing"
)

func TestRemoteDesktopRequests(t *testing.T) {
	c, reqs := newTestClient(t, nil)
	ctx := context.Background()
	c.CreateRemoteDesktop(ctx, "rd1", Params{"hostname": "h"})
	c.UpdateRemoteDesktop(ctx, 5, "rd1", Params{"hostname": "h2"})
	c.GetRemoteDesktopDownloadToken(ctx, 9, "mp4")
	r := *reqs
	if r[0].Method != http.MethodPost || r[0].Path != "/api/v1/rdp/" || r[0].Body["name"] != "rd1" || r[0].Body["details"] == nil {
		t.Fatalf("create: %+v", r[0])
	}
	if r[1].Method != http.MethodPut || r[1].Path != "/api/v1/rdp/5" || r[1].Body["name"] != "rd1" {
		t.Fatalf("update: %+v", r[1])
	}
	if r[2].Method != http.MethodGet || r[2].Path != "/api/v1/rdp/9/download/mp4" {
		t.Fatalf("download token: %+v", r[2])
	}
}
