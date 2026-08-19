package httpclient

import (
	"compress/gzip"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/msdrakula/J.A.R.V.I.S/internal/config"
)

type Client struct {
	httpClient *http.Client
	cfg        config.HTTPConfig
	rateTicker <-chan time.Time
	mu         sync.Mutex
}

type RequestOptions struct {
	Method          string
	URL             string
	Headers         map[string]string
	Body            io.Reader
	FollowRedirects bool
}

type Response struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
	Duration   time.Duration
}

func NewClient(cfg config.HTTPConfig) (*Client, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.InsecureSkipVerify},
	}

	if cfg.Proxy != "" {
		proxyURL, err := url.Parse(cfg.Proxy)
		if err != nil {
			return nil, fmt.Errorf("parse proxy: %w", err)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	jar := &cookieJar{store: map[string][]*http.Cookie{}}
	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(cfg.TimeoutSeconds) * time.Second,
		Jar:       jar,
	}

	var ticker <-chan time.Time
	if cfg.RateLimitPerSec > 0 {
		t := time.NewTicker(time.Second / time.Duration(cfg.RateLimitPerSec))
		ticker = t.C
	}

	return &Client{httpClient: client, cfg: cfg, rateTicker: ticker}, nil
}

func (c *Client) Do(opts RequestOptions) (*Response, error) {
	var lastErr error

	for attempt := 0; attempt <= c.cfg.RetryCount; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(c.cfg.RetryDelayMillis) * time.Millisecond)
		}

		if c.rateTicker != nil {
			<-c.rateTicker
		}

		ctx := context.Background()
		req, err := http.NewRequestWithContext(ctx, opts.Method, opts.URL, opts.Body)
		if err != nil {
			return nil, err
		}

		for k, v := range opts.Headers {
			req.Header.Set(k, v)
		}

		if req.Header.Get("User-Agent") == "" && len(c.cfg.UserAgents) > 0 {
			req.Header.Set("User-Agent", c.cfg.UserAgents[rand.Intn(len(c.cfg.UserAgents))])
		}

		start := time.Now()
		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		body, readErr := readBody(resp)
		if readErr != nil {
			resp.Body.Close()
			lastErr = readErr
			continue
		}
		resp.Body.Close()

		return &Response{
			StatusCode: resp.StatusCode,
			Headers:    resp.Header.Clone(),
			Body:       body,
			Duration:   time.Since(start),
		}, nil
	}

	return nil, lastErr
}

func readBody(resp *http.Response) ([]byte, error) {
	reader := resp.Body
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		reader = gz
	}
	return io.ReadAll(reader)
}

type cookieJar struct {
	mu    sync.Mutex
	store map[string][]*http.Cookie
}

func (j *cookieJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.store[u.Host] = cookies
}

func (j *cookieJar) Cookies(u *url.URL) []*http.Cookie {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.store[u.Host]
}
