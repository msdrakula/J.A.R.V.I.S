package compliance

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/msdrakula/J.A.R.V.I.S/internal/httpclient"
	"github.com/msdrakula/J.A.R.V.I.S/internal/storage"
)

type Matcher struct {
	Type      string   `yaml:"type"`
	Part      string   `yaml:"part"`
	Words     []string `yaml:"words"`
	Regex     []string `yaml:"regex"`
	Condition string   `yaml:"condition"`
	Name      string   `yaml:"name"`
	Value     string   `yaml:"value"`
}

type Rule struct {
	ID             string    `yaml:"id"`
	Description    string    `yaml:"description"`
	Path           string    `yaml:"path"`
	ExpectedStatus int       `yaml:"expected_status"`
	Severity       string    `yaml:"severity"`
	Matchers       []Matcher `yaml:"matchers"`
}

type Checker struct {
	client *httpclient.Client
	store  *storage.Store
}

func New(client *httpclient.Client, store *storage.Store) *Checker {
	return &Checker{client: client, store: store}
}

func LoadRules(path string) ([]Rule, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rules []Rule
	if err := yaml.Unmarshal(data, &rules); err != nil {
		return nil, err
	}
	return rules, nil
}

func (c *Checker) Check(scanID, baseURL string, rules []Rule) error {
	if c == nil || c.client == nil {
		return fmt.Errorf("compliance checker is not initialized")
	}
	if len(rules) == 0 || strings.TrimSpace(baseURL) == "" {
		return nil
	}
	for _, rule := range rules {
		url := strings.TrimRight(baseURL, "/") + "/" + strings.TrimLeft(rule.Path, "/")
		resp, err := c.client.Do(httpclient.RequestOptions{Method: "GET", URL: url, FollowRedirects: true})
		if err != nil {
			return fmt.Errorf("request %s: %w", url, err)
		}
		if resp == nil {
			continue
		}

		matched := false
		evidence := []string{}

		if rule.ExpectedStatus != 0 && resp.StatusCode != rule.ExpectedStatus {
			matched = true
			evidence = append(evidence, fmt.Sprintf("expected=%d actual=%d", rule.ExpectedStatus, resp.StatusCode))
		}

		for _, matcher := range rule.Matchers {
			ok, note := matchResponse(matcher, resp)
			if ok {
				matched = true
				evidence = append(evidence, note)
			}
		}

		if matched {
			finding := storage.Finding{
				Host:        baseURL,
				URL:         url,
				Severity:    rule.Severity,
				Category:    "compliance",
				Name:        rule.ID,
				Description: rule.Description,
				Evidence:    strings.Join(evidence, "; "),
			}
			if c.store != nil {
				if err := c.store.AddFinding(scanID, finding); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func matchResponse(m Matcher, resp *httpclient.Response) (bool, string) {
	part := strings.ToLower(m.Part)
	condition := strings.ToLower(m.Condition)

	switch strings.ToLower(m.Type) {
	case "status":
		for _, word := range m.Words {
			if fmt.Sprintf("%d", resp.StatusCode) == word {
				return true, "status matched " + word
			}
		}
	case "header":
		if m.Name == "" {
			return false, ""
		}
		value := resp.Headers.Get(m.Name)
		if m.Value != "" {
			if strings.Contains(strings.ToLower(value), strings.ToLower(m.Value)) {
				return true, fmt.Sprintf("header %s matched", m.Name)
			}
			return false, ""
		}
		if value != "" {
			return true, fmt.Sprintf("header %s present", m.Name)
		}
	case "word":
		if part != "body" {
			return false, ""
		}
		body := strings.ToLower(string(resp.Body))
		if condition == "and" {
			for _, word := range m.Words {
				if !strings.Contains(body, strings.ToLower(word)) {
					return false, ""
				}
			}
			return true, "body words matched"
		}
		for _, word := range m.Words {
			if strings.Contains(body, strings.ToLower(word)) {
				return true, "body word matched: " + word
			}
		}
	case "regex":
		if part != "body" {
			return false, ""
		}
		body := string(resp.Body)
		for _, pattern := range m.Regex {
			re, err := regexp.Compile(pattern)
			if err != nil {
				continue
			}
			if re.MatchString(body) {
				return true, "body regex matched"
			}
		}
	}
	return false, ""
}
