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
	"strings"
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
	cfg.Normalize()

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
	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
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
	if c == nil || c.httpClient == nil {
		return nil, fmt.Errorf("http client is not initialized")
	}
	if strings.TrimSpace(opts.URL) == "" {
		return nil, fmt.Errorf("url is required")
	}
	if opts.Method == "" {
		opts.Method = http.MethodGet
	}

	var lastErr error

	retries := c.cfg.RetryCount
	if retries < 0 {
		retries = 0
	}

	for attempt := 0; attempt <= retries; attempt++ {
		if attempt > 0 {
			delay := time.Duration(c.cfg.RetryDelayMillis) * time.Millisecond
			if delay > 0 {
				time.Sleep(delay)
			}
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
		if resp == nil {
			lastErr = fmt.Errorf("empty response from %s", opts.URL)
			continue
		}

		body, readErr := readBody(resp)
		if readErr != nil {
			resp.Body.Close()
			lastErr = readErr
			continue
		}
		resp.Body.Close()

		headers := http.Header{}
		if resp.Header != nil {
			headers = resp.Header.Clone()
		}

		return &Response{
			StatusCode: resp.StatusCode,
			Headers:    headers,
			Body:       body,
			Duration:   time.Since(start),
		}, nil
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("request failed: %s", opts.URL)
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
	if j == nil || u == nil {
		return
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.store == nil {
		j.store = map[string][]*http.Cookie{}
	}
	j.store[u.Host] = cookies
}

func (j *cookieJar) Cookies(u *url.URL) []*http.Cookie {
	if j == nil || u == nil {
		return nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.store == nil {
		return nil
	}
	return j.store[u.Host]
}
