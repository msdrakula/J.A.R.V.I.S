package cli

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/msdrakula/J.A.R.V.I.S/internal/config"
	"github.com/msdrakula/J.A.R.V.I.S/internal/httpclient"
	"github.com/msdrakula/J.A.R.V.I.S/internal/modules/availability"
	"github.com/msdrakula/J.A.R.V.I.S/internal/modules/compliance"
	"github.com/msdrakula/J.A.R.V.I.S/internal/modules/recon"
	"github.com/msdrakula/J.A.R.V.I.S/internal/modules/resilience"
	"github.com/msdrakula/J.A.R.V.I.S/internal/modules/urlaudit"
	"github.com/msdrakula/J.A.R.V.I.S/internal/modules/waflib"
	"github.com/msdrakula/J.A.R.V.I.S/internal/storage"
)

var defaultIPPorts = []int{22, 80, 443}

type targetKind int

const (
	targetIP targetKind = iota
	targetWeb
)

type parsedTarget struct {
	Raw     string
	Kind    targetKind
	Host    string
	BaseURL string
	Ports   []int
}

func newScanCmd() *cobra.Command {
	var (
		target      string
		targetAlias string
		level       int
		ports       []int
	)

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Audit a URL, domain, or IP",
		Example: `  jarvis scan -u https://example.com -o ./results
  jarvis scan -u example.com -o ./results
  jarvis scan -u 192.168.1.10 -o ./results
  jarvis scan --target https://example.com --level 2 -o ./results`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(target) == "" {
				target = targetAlias
			}
			if strings.TrimSpace(target) == "" {
				return fmt.Errorf("target is required: jarvis scan -u https://example.com")
			}

			cfg, log, store, dbPath, err := loadRuntime()
			if err != nil {
				return err
			}
			if store != nil {
				defer store.Close()
			}
			if log == nil {
				log = zap.NewNop()
			}
			if cfg == nil {
				cfg = config.Defaults()
			}
			cfg.Normalize()

			profile, err := config.ProfileForLevel(level)
			if err != nil {
				return err
			}
			cfg.ApplyProfile(profile)
			log.Info("audit profile", zap.String("profile", profile.Name), zap.Int("level", profile.Level))

			parsed, err := parseScanTarget(target)
			if err != nil {
				return err
			}
			if parsed.Kind == targetIP && len(ports) > 0 {
				parsed.Ports = ports
			}

			client, err := httpclient.NewClient(cfg.HTTP)
			if err != nil {
				return err
			}

			interrupted := func(scanID string) bool {
				if cmd.Context() != nil && cmd.Context().Err() != nil {
					if store != nil {
						_ = store.UpdateScanStatus(scanID, "paused")
					}
					return true
				}
				return false
			}

			var scanID string
			var errs []string
			if parsed.Kind == targetIP {
				scanID, errs, err = runIPScan(store, cfg, parsed, interrupted)
			} else {
				scanID, errs, err = runWebScan(store, cfg, client, parsed, interrupted)
			}
			if err != nil {
				return err
			}

			log.Info("audit completed", zap.String("db", dbPath), zap.String("scan_id", scanID), zap.String("target", parsed.Raw))
			fmt.Println("Scan completed:", scanID)
			if len(errs) > 0 {
				if store != nil {
					_ = store.UpdateScanStatus(scanID, "failed")
				}
				fmt.Println("Warnings:")
				for _, item := range errs {
					fmt.Println("-", item)
				}
			} else if store != nil {
				_ = store.UpdateScanStatus(scanID, "completed")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&target, "url", "u", "", "Target URL, domain, or IP")
	cmd.Flags().StringVar(&targetAlias, "target", "", "Alias for -u/--url")
	cmd.Flags().IntVar(&level, "level", 3, "Audit intensity level 1-5 (1=stealth, 3=normal, 5=thorough)")
	cmd.Flags().IntSliceVarP(&ports, "ports", "p", nil, "Ports for IP targets (default: 22,80,443)")
	return cmd
}

func parseScanTarget(raw string) (parsedTarget, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return parsedTarget{}, fmt.Errorf("empty target")
	}

	lower := strings.ToLower(raw)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		parsed, err := url.Parse(raw)
		if err != nil || parsed == nil || parsed.Host == "" {
			return parsedTarget{}, fmt.Errorf("invalid URL %q", raw)
		}
		host := parsed.Hostname()
		if host == "" {
			return parsedTarget{}, fmt.Errorf("invalid URL host %q", raw)
		}
		base := parsed.Scheme + "://" + parsed.Host
		return parsedTarget{Raw: raw, Kind: targetWeb, Host: host, BaseURL: base}, nil
	}

	if host, portStr, err := net.SplitHostPort(raw); err == nil {
		port, convErr := strconv.Atoi(portStr)
		if convErr != nil || port <= 0 {
			return parsedTarget{}, fmt.Errorf("invalid port in %q", raw)
		}
		if net.ParseIP(host) != nil {
			return parsedTarget{Raw: raw, Kind: targetIP, Host: host, Ports: []int{port}}, nil
		}
		return parsedTarget{
			Raw:     raw,
			Kind:    targetWeb,
			Host:    host,
			BaseURL: "https://" + raw,
		}, nil
	}

	if ip := net.ParseIP(raw); ip != nil {
		return parsedTarget{Raw: raw, Kind: targetIP, Host: raw, Ports: append([]int{}, defaultIPPorts...)}, nil
	}

	host := strings.TrimSuffix(raw, "/")
	host = strings.TrimPrefix(host, "www.")
	if host == "" {
		return parsedTarget{}, fmt.Errorf("invalid domain %q", raw)
	}
	return parsedTarget{
		Raw:     raw,
		Kind:    targetWeb,
		Host:    host,
		BaseURL: "https://" + host,
	}, nil
}

func runIPScan(store *storage.Store, cfg *config.Config, target parsedTarget, interrupted func(string) bool) (string, []string, error) {
	modules := []string{"availability"}
	outDir := "./results"
	if cfg != nil && cfg.OutputDir != "" {
		outDir = cfg.OutputDir
	}
	scanID, err := createScan(store, target.Raw, modules, outDir)
	if err != nil {
		return "", nil, err
	}

	ports := target.Ports
	if len(ports) == 0 {
		ports = defaultIPPorts
	}

	checker := availability.New(store)
	var errs []string
	for _, port := range ports {
		if interrupted(scanID) {
			return scanID, errs, fmt.Errorf("scan interrupted")
		}
		result, err := checker.CheckTCP(scanID, target.Host, port)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		if result != nil {
			fmt.Printf("%s:%d %s %s\n", result.Host, result.Port, result.State, result.Service)
		}
	}
	return scanID, errs, nil
}

func runWebScan(store *storage.Store, cfg *config.Config, client *httpclient.Client, target parsedTarget, interrupted func(string) bool) (string, []string, error) {
	if client == nil {
		return "", nil, fmt.Errorf("http client is not initialized")
	}

	modules := []string{"recon", "urlaudit", "compliance", "waf", "resilience"}
	outDir := "./results"
	rulesPath := "rules.yaml"
	wafPath := "waf_signatures.yaml"
	if cfg != nil {
		if cfg.OutputDir != "" {
			outDir = cfg.OutputDir
		}
		if cfg.RulesPath != "" {
			rulesPath = cfg.RulesPath
		}
		if cfg.WAFSignaturesPath != "" {
			wafPath = cfg.WAFSignaturesPath
		}
	}

	scanID, err := createScan(store, target.Raw, modules, outDir)
	if err != nil {
		return "", nil, err
	}

	var errs []string
	reconAuditor := recon.New(client, store)
	if interrupted(scanID) {
		return scanID, errs, fmt.Errorf("scan interrupted")
	}
	if _, err := reconAuditor.ResolveDNS(scanID, target.Host); err != nil {
		errs = append(errs, err.Error())
	}
	if _, err := reconAuditor.ReadTLS(scanID, target.Host); err != nil {
		errs = append(errs, err.Error())
	}
	if _, err := reconAuditor.FetchRobots(scanID, target.BaseURL); err != nil {
		errs = append(errs, err.Error())
	}
	if _, err := reconAuditor.FetchSitemap(scanID, target.BaseURL); err != nil {
		errs = append(errs, err.Error())
	}
	if _, err := reconAuditor.ExtractFormParameters(scanID, target.BaseURL); err != nil {
		errs = append(errs, err.Error())
	}

	if interrupted(scanID) {
		return scanID, errs, fmt.Errorf("scan interrupted")
	}
	if sigPath := config.ExistingFile(wafPath); sigPath != "" {
		wafSigs, err := waflib.LoadSignatures(sigPath)
		if err != nil {
			errs = append(errs, err.Error())
		} else {
			wafDetector := waflib.New(client, store, wafSigs)
			detections, err := wafDetector.Detect(scanID, target.BaseURL)
			if err != nil {
				errs = append(errs, err.Error())
			} else {
				for _, det := range detections {
					fmt.Printf("[+] WAF Detected: %s\n", det.Name)
					for _, ev := range det.Evidence {
						fmt.Printf("    Evidence: %s\n", ev)
					}
				}
			}
		}
	}

	paths := defaultAuditPaths()
	urlAuditor := urlaudit.New(client, store)
	if interrupted(scanID) {
		return scanID, errs, fmt.Errorf("scan interrupted")
	}
	if _, err := urlAuditor.CheckPaths(scanID, target.BaseURL, paths); err != nil {
		errs = append(errs, err.Error())
	}

	var rules []compliance.Rule
	if rulePath := config.ExistingFile(rulesPath); rulePath != "" {
		loaded, err := compliance.LoadRules(rulePath)
		if err != nil {
			errs = append(errs, err.Error())
		} else {
			rules = loaded
		}
	}
	complianceChecker := compliance.New(client, store)
	if interrupted(scanID) {
		return scanID, errs, fmt.Errorf("scan interrupted")
	}
	if err := complianceChecker.Check(scanID, target.BaseURL, rules); err != nil {
		errs = append(errs, err.Error())
	}

	resilienceChecker := resilience.New(client, store)
	if interrupted(scanID) {
		return scanID, errs, fmt.Errorf("scan interrupted")
	}
	if err := resilienceChecker.Check(scanID); err != nil {
		errs = append(errs, err.Error())
	}

	return scanID, errs, nil
}

func defaultAuditPaths() []string {
	if paths, err := loadWordlist("wordlists/common_paths.txt"); err == nil && len(paths) > 0 {
		return paths
	}
	return []string{"/", "/robots.txt", "/sitemap.xml"}
}
