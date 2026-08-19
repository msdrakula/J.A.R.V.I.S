package recon

import (
	"context"
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/msdrakula/J.A.R.V.I.S/internal/httpclient"
	"github.com/msdrakula/J.A.R.V.I.S/internal/storage"
)

type Auditor struct {
	client *httpclient.Client
	store  *storage.Store
}

type DNSResult struct {
	Domain string
	Records []storage.DNSRecord
}

type TLSSummary struct {
	Domain    string
	Subject   string
	Issuer    string
	NotBefore time.Time
	NotAfter  time.Time
}

type RobotsResult struct {
	URL   string
	Rules []string
}

type SitemapResult struct {
	URL  string
	URLs []string
}

func New(client *httpclient.Client, store *storage.Store) *Auditor {
	return &Auditor{client: client, store: store}
}

func (a *Auditor) requireClient() error {
	if a == nil || a.client == nil {
		return fmt.Errorf("recon auditor is not initialized")
	}
	return nil
}

func (a *Auditor) ResolveDNS(scanID, domain string) (*DNSResult, error) {
	if a == nil {
		return nil, fmt.Errorf("recon auditor is not initialized")
	}
	result := &DNSResult{Domain: domain}
	resolver := net.DefaultResolver
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ips, err := resolver.LookupIP(ctx, "ip", domain)
	if err == nil {
		for _, ip := range ips {
			recordType := "A"
			if ip.To4() == nil {
				recordType = "AAAA"
			}
			rec := storage.DNSRecord{Domain: domain, RecordType: recordType, Value: ip.String()}
			result.Records = append(result.Records, rec)
			if a.store != nil {
				_ = a.store.AddDNSRecord(scanID, rec)
			}
		}
	}

	mxRecords, err := resolver.LookupMX(ctx, domain)
	if err == nil {
		for _, mx := range mxRecords {
			rec := storage.DNSRecord{Domain: domain, RecordType: "MX", Value: fmt.Sprintf("%s %d", mx.Host, mx.Pref)}
			result.Records = append(result.Records, rec)
			if a.store != nil {
				_ = a.store.AddDNSRecord(scanID, rec)
			}
		}
	}

	txtRecords, err := resolver.LookupTXT(ctx, domain)
	if err == nil {
		for _, txt := range txtRecords {
			rec := storage.DNSRecord{Domain: domain, RecordType: "TXT", Value: txt}
			result.Records = append(result.Records, rec)
			if a.store != nil {
				_ = a.store.AddDNSRecord(scanID, rec)
			}
		}
	}

	return result, nil
}

func (a *Auditor) ReadTLS(scanID, domain string) (*TLSSummary, error) {
	if a == nil {
		return nil, fmt.Errorf("recon auditor is not initialized")
	}
	address := net.JoinHostPort(domain, "443")
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", address, &tls.Config{ServerName: domain})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no certificates found")
	}

	cert := state.PeerCertificates[0]
	summary := &TLSSummary{
		Domain:    domain,
		Subject:   cert.Subject.String(),
		Issuer:    cert.Issuer.String(),
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
	}

	if a.store != nil {
		_ = a.store.AddTLSInfo(scanID, storage.TLSInfo{
			Domain:    summary.Domain,
			Subject:   summary.Subject,
			Issuer:    summary.Issuer,
			NotBefore: summary.NotBefore.Format(time.RFC3339),
			NotAfter:  summary.NotAfter.Format(time.RFC3339),
		})

		daysLeft := int(time.Until(summary.NotAfter).Hours() / 24)
		if daysLeft < 30 {
			severity := "low"
			if daysLeft < 14 {
				severity = "medium"
			}
			_ = a.store.AddFinding(scanID, storage.Finding{
				Host:        summary.Domain,
				URL:         "https://" + summary.Domain,
				Severity:    severity,
				Category:    "tls",
				Name:        "TLS certificate expiring soon",
				Description: "TLS certificate expires in less than 30 days",
				Evidence:    summary.NotAfter.Format(time.RFC3339),
			})
		}
	}

	return summary, nil
}

func (a *Auditor) FetchRobots(scanID, baseURL string) (*RobotsResult, error) {
	if err := a.requireClient(); err != nil {
		return nil, err
	}
	url := strings.TrimRight(baseURL, "/") + "/robots.txt"
	resp, err := a.client.Do(httpclient.RequestOptions{Method: "GET", URL: url, FollowRedirects: true})
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return &RobotsResult{URL: url}, nil
	}

	lines := strings.Split(string(resp.Body), "\n")
	rules := []string{}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		rules = append(rules, line)
	}

	if a.store != nil {
		_ = a.store.AddAssetPath(scanID, storage.AssetPath{URL: url, StatusCode: resp.StatusCode, Size: len(resp.Body), ContentType: resp.Headers.Get("Content-Type")})
	}

	return &RobotsResult{URL: url, Rules: rules}, nil
}

func (a *Auditor) FetchSitemap(scanID, baseURL string) (*SitemapResult, error) {
	if err := a.requireClient(); err != nil {
		return nil, err
	}
	url := strings.TrimRight(baseURL, "/") + "/sitemap.xml"
	resp, err := a.client.Do(httpclient.RequestOptions{Method: "GET", URL: url, FollowRedirects: true})
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return &SitemapResult{URL: url}, nil
	}

	type urlSet struct {
		URLs []struct {
			Loc string `xml:"loc"`
		} `xml:"url"`
	}

	var parsed urlSet
	if err := xml.Unmarshal(resp.Body, &parsed); err != nil {
		return nil, err
	}

	urls := []string{}
	for _, item := range parsed.URLs {
		urls = append(urls, item.Loc)
	}

	if a.store != nil {
		_ = a.store.AddAssetPath(scanID, storage.AssetPath{URL: url, StatusCode: resp.StatusCode, Size: len(resp.Body), ContentType: resp.Headers.Get("Content-Type")})
	}

	return &SitemapResult{URL: url, URLs: urls}, nil
}

func (a *Auditor) ExtractFormParameters(scanID, rawURL string) ([]string, error) {
	if err := a.requireClient(); err != nil {
		return nil, err
	}
	resp, err := a.client.Do(httpclient.RequestOptions{Method: "GET", URL: rawURL, FollowRedirects: true})
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, nil
	}
	return a.ExtractFormParametersFromBody(scanID, rawURL, resp.Body)
}

func (a *Auditor) ExtractFormParametersFromBody(scanID, rawURL string, body []byte) ([]string, error) {
	text := string(body)
	params := map[string]struct{}{}

	inputRe := regexp.MustCompile(`(?i)<input[^>]*name=["']([^"']+)["'][^>]*>`)
	formRe := regexp.MustCompile(`(?i)<form[^>]*name=["']([^"']+)["'][^>]*>`)

	for _, match := range inputRe.FindAllStringSubmatch(text, -1) {
		params[match[1]] = struct{}{}
	}
	for _, match := range formRe.FindAllStringSubmatch(text, -1) {
		params[match[1]] = struct{}{}
	}

	result := make([]string, 0, len(params))
	for name := range params {
		result = append(result, name)
		if a.store != nil {
			_ = a.store.AddParameter(scanID, storage.Parameter{URL: rawURL, Name: name, ParamType: "form", Source: "html_form"})
		}
	}

	return result, nil
}

func (a *Auditor) FetchBody(rawURL string) ([]byte, error) {
	if err := a.requireClient(); err != nil {
		return nil, err
	}
	resp, err := a.client.Do(httpclient.RequestOptions{Method: "GET", URL: rawURL, FollowRedirects: true})
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, nil
	}
	return io.ReadAll(strings.NewReader(string(resp.Body)))
}
