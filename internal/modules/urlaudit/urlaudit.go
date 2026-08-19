package urlaudit

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/msdrakula/J.A.R.V.I.S/internal/httpclient"
	"github.com/msdrakula/J.A.R.V.I.S/internal/storage"
)

type Auditor struct {
	client *httpclient.Client
	store  *storage.Store
}

type PathResult struct {
	URL         string
	StatusCode  int
	Size        int
	ContentType string
	Headers     map[string][]string
}

func New(client *httpclient.Client, store *storage.Store) *Auditor {
	return &Auditor{client: client, store: store}
}

func (a *Auditor) CheckPaths(scanID, baseURL string, paths []string) ([]PathResult, error) {
	if a == nil || a.client == nil {
		return nil, fmt.Errorf("url auditor is not initialized")
	}
	if strings.TrimSpace(baseURL) == "" {
		return nil, fmt.Errorf("base url is required")
	}

	results := []PathResult{}
	baselineStatus := 0
	baselineSize := -1

	for _, path := range paths {
		fullURL := strings.TrimRight(baseURL, "/") + "/" + strings.TrimLeft(path, "/")
		resp, err := a.client.Do(httpclient.RequestOptions{Method: "GET", URL: fullURL, FollowRedirects: true})
		if err != nil {
			return results, fmt.Errorf("request %s: %w", fullURL, err)
		}
		if resp == nil {
			continue
		}

		result := PathResult{
			URL:         fullURL,
			StatusCode:  resp.StatusCode,
			Size:        len(resp.Body),
			ContentType: resp.Headers.Get("Content-Type"),
			Headers:     resp.Headers,
		}

		if baselineSize == -1 && resp.StatusCode == 404 {
			baselineStatus = resp.StatusCode
			baselineSize = result.Size
		}

		if baselineSize != -1 && resp.StatusCode == baselineStatus && result.Size == baselineSize {
			continue
		}

		if isInterestingStatus(result.StatusCode) {
			results = append(results, result)
			if a.store != nil {
				_ = a.store.AddPath(scanID, storage.AssetPath{URL: result.URL, StatusCode: result.StatusCode, Size: result.Size, ContentType: result.ContentType})
				_ = a.store.AddAssetPath(scanID, storage.AssetPath{URL: result.URL, StatusCode: result.StatusCode, Size: result.Size, ContentType: result.ContentType})
				for _, finding := range missingSecurityHeaders(result.URL, resp.Headers) {
					_ = a.store.AddFinding(scanID, finding)
				}
			}
		}
	}

	return results, nil
}

func isInterestingStatus(code int) bool {
	switch code {
	case 200, 201, 202, 204, 301, 302, 307, 308, 401, 403:
		return true
	default:
		return false
	}
}

func missingSecurityHeaders(rawURL string, headers map[string][]string) []storage.Finding {
	required := []string{
		"Strict-Transport-Security",
		"X-Frame-Options",
		"X-Content-Type-Options",
		"Content-Security-Policy",
	}

	u, _ := url.Parse(rawURL)
	host := ""
	if u != nil {
		host = u.Host
	}

	findings := []storage.Finding{}
	for _, header := range required {
		if headers[header] == nil && headers[strings.ToLower(header)] == nil {
			findings = append(findings, storage.Finding{
				Host:        host,
				URL:         rawURL,
				Severity:    "low",
				Category:    "security-header",
				Name:        "Missing security header",
				Description: "Missing security header: " + header,
				Evidence:    header,
			})
		}
	}
	return findings
}

func VisualizeTree(results []PathResult) string {
	paths := make([]string, 0, len(results))
	for _, result := range results {
		if result.StatusCode >= 200 && result.StatusCode < 400 {
			paths = append(paths, fmt.Sprintf("[%d] %s", result.StatusCode, result.URL))
		}
	}
	sort.Strings(paths)

	var b strings.Builder
	for i, path := range paths {
		branch := "├─"
		if i == len(paths)-1 {
			branch = "└─"
		}
		b.WriteString(branch + " " + path + "\n")
	}
	return b.String()
}
