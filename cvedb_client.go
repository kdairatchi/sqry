package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

const cvedbBase = "https://cvedb.shodan.io"

type CVEDBClient struct {
	hc *http.Client
}

func NewCVEDBClient(timeout time.Duration) *CVEDBClient {
	return &CVEDBClient{hc: &http.Client{Timeout: timeout}}
}

func (c *CVEDBClient) getJSON(ctx context.Context, path string, q url.Values, out any) error {
	u := fmt.Sprintf("%s%s", cvedbBase, path)
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", randomUserAgent())

	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("cvedb: %s -> HTTP %d", u, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *CVEDBClient) GetCVE(ctx context.Context, id string) (*CVE, error) {
	var v CVE
	err := c.getJSON(ctx, "/cve/"+url.PathEscape(id), nil, &v)
	return &v, err
}

func (c *CVEDBClient) GetCVEs(ctx context.Context, params url.Values) ([]CVE, error) {
	var v CVEsResp
	if err := c.getJSON(ctx, "/cves", params, &v); err != nil {
		return nil, err
	}
	return v.CVEs, nil
}

func (c *CVEDBClient) GetCPEs(ctx context.Context, product string) ([]string, error) {
	q := url.Values{"product": []string{product}}
	var v CPEsResp
	if err := c.getJSON(ctx, "/cpes", q, &v); err != nil {
		return nil, err
	}
	return v.CPEs, nil
}
