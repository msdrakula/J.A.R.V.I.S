package config

import (
	"os"
	"strings"

	"github.com/spf13/viper"
)

type Config struct {
	OutputDir         string        `mapstructure:"output_dir"`
	HTTP              HTTPConfig    `mapstructure:"http"`
	Inventory         InventoryFile `mapstructure:"inventory"`
	ReportDir         string        `mapstructure:"report_dir"`
	RulesPath         string        `mapstructure:"rules_path"`
	WAFSignaturesPath string        `mapstructure:"waf_signatures_path"`
	Verbose           bool          `mapstructure:"verbose"`
	Quiet             bool          `mapstructure:"quiet"`
}

type HTTPConfig struct {
	TimeoutSeconds    int      `mapstructure:"timeout_seconds"`
	MaxRedirects      int      `mapstructure:"max_redirects"`
	RetryCount        int      `mapstructure:"retry_count"`
	RetryDelayMillis  int      `mapstructure:"retry_delay_millis"`
	RateLimitPerSec   int      `mapstructure:"rate_limit_per_sec"`
	Proxy             string   `mapstructure:"proxy"`
	UserAgents        []string `mapstructure:"user_agents"`
	InsecureSkipVerify bool    `mapstructure:"insecure_skip_verify"`
}

type InventoryFile struct {
	Domains []string          `mapstructure:"domains"`
	Hosts   []InventoryHost   `mapstructure:"hosts"`
	URLs    []InventoryURL    `mapstructure:"urls"`
}

type InventoryHost struct {
	Address string `mapstructure:"address"`
	Ports   []int  `mapstructure:"ports"`
}

type InventoryURL struct {
	Base  string   `mapstructure:"base"`
	Paths []string `mapstructure:"paths"`
}

// Defaults возвращает рабочую конфигурацию без YAML-файла.
func Defaults() *Config {
	cfg := &Config{
		OutputDir:         "./results",
		ReportDir:         "./reports",
		RulesPath:         "rules.yaml",
		WAFSignaturesPath: "waf_signatures.yaml",
		HTTP: HTTPConfig{
			TimeoutSeconds:   15,
			MaxRedirects:     5,
			RetryCount:       2,
			RetryDelayMillis: 300,
			RateLimitPerSec:  5,
			UserAgents:       []string{"jarvis-safe-audit/1.0"},
		},
	}
	return cfg
}

// Normalize заполняет нулевые поля безопасными значениями. Никогда не паникует.
func (c *Config) Normalize() {
	if c == nil {
		return
	}
	if c.OutputDir == "" {
		c.OutputDir = "./results"
	}
	if c.ReportDir == "" {
		c.ReportDir = "./reports"
	}
	c.HTTP.Normalize()
}

// Normalize заполняет HTTP-дефолты, чтобы клиент не делил на ноль и не брал пустой UA.
func (h *HTTPConfig) Normalize() {
	if h == nil {
		return
	}
	if h.TimeoutSeconds <= 0 {
		h.TimeoutSeconds = 15
	}
	if h.MaxRedirects < 0 {
		h.MaxRedirects = 5
	}
	if h.RetryCount < 0 {
		h.RetryCount = 0
	}
	if h.RetryDelayMillis < 0 {
		h.RetryDelayMillis = 0
	}
	if h.RateLimitPerSec < 0 {
		h.RateLimitPerSec = 0
	}
	if len(h.UserAgents) == 0 {
		h.UserAgents = []string{"jarvis-safe-audit/1.0"}
	}
}

// ExistingFile возвращает path, если файл есть, иначе пустую строку.
func ExistingFile(path string) string {
	if path == "" {
		return ""
	}
	if _, err := os.Stat(path); err != nil {
		return ""
	}
	return path
}

func Load(path string) (*Config, error) {
	cfg := Defaults()
	if strings.TrimSpace(path) == "" {
		return cfg, nil
	}

	v := viper.New()
	v.SetConfigFile(path)
	v.SetConfigType("yaml")
	v.SetEnvPrefix("JARVIS")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	v.SetDefault("output_dir", cfg.OutputDir)
	v.SetDefault("report_dir", cfg.ReportDir)
	v.SetDefault("rules_path", cfg.RulesPath)
	v.SetDefault("waf_signatures_path", cfg.WAFSignaturesPath)
	v.SetDefault("http.timeout_seconds", cfg.HTTP.TimeoutSeconds)
	v.SetDefault("http.max_redirects", cfg.HTTP.MaxRedirects)
	v.SetDefault("http.retry_count", cfg.HTTP.RetryCount)
	v.SetDefault("http.retry_delay_millis", cfg.HTTP.RetryDelayMillis)
	v.SetDefault("http.rate_limit_per_sec", cfg.HTTP.RateLimitPerSec)
	v.SetDefault("http.user_agents", cfg.HTTP.UserAgents)
	v.SetDefault("http.insecure_skip_verify", false)

	if err := v.ReadInConfig(); err != nil {
		return nil, err
	}

	if err := v.Unmarshal(cfg); err != nil {
		return nil, err
	}
	cfg.Normalize()
	return cfg, nil
}
