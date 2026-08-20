// Package billing talks to two external APIs and one internal service.
package billing

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
)

const stripeBase = "https://api.stripe.com"

// Client holds its base URL in a field, which is the shape the scanner has to
// resolve one hop to make sense of most real codebases.
type Client struct {
	hc      *http.Client
	baseURL string
}

func New() *Client {
	return &Client{hc: &http.Client{}, baseURL: "https://api.acme.example.com"}
}

func (c *Client) AddUser(ctx context.Context) {
	req, _ := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/api/v1/user/add")
	c.hc.Do(req)
}

func (c *Client) GetUser(ctx context.Context, userID string) {
	c.hc.Get(fmt.Sprintf("%s/api/v1/users/%s", c.baseURL, userID))
}

func (c *Client) ListInvoices() {
	http.Get(stripeBase + "/v1/invoices")
}

func (c *Client) CreateCharge() {
	http.Post(stripeBase+"/v1/charges", "application/json", nil)
}

// The search service host comes from the environment, so it stays symbolic.
func (c *Client) Search(q string) {
	http.Get(os.Getenv("SEARCH_BASE_URL") + "/search")
}

func (c *Client) Reports() {
	u, _ := url.JoinPath(stripeBase, "v1", "reports")
	http.Get(u)
}

// A localhost call is a development detail, not an external dependency.
func (c *Client) DebugPing() {
	http.Get("http://localhost:8080/debug/ping")
}
