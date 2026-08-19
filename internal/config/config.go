package config

import (
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

func Load(path string) (*Config, error) {
	v := viper.New()
	v.SetConfigFile(path)
	v.SetConfigType("yaml")
	v.SetEnvPrefix("JARVIS")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	v.SetDefault("output_dir", "./results")
	v.SetDefault("report_dir", "./reports")
	v.SetDefault("rules_path", "rules.yaml")
	v.SetDefault("waf_signatures_path", "waf_signatures.yaml")
	v.SetDefault("http.timeout_seconds", 15)
	v.SetDefault("http.max_redirects", 5)
	v.SetDefault("http.retry_count", 2)
	v.SetDefault("http.retry_delay_millis", 300)
	v.SetDefault("http.rate_limit_per_sec", 5)
	v.SetDefault("http.user_agents", []string{"jarvis-safe-audit/1.0"})
	v.SetDefault("http.insecure_skip_verify", false)

	if path != "" {
		if err := v.ReadInConfig(); err != nil {
			return nil, err
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
