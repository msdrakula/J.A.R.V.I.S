package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/msdrakula/J.A.R.V.I.S/internal/config"
	"github.com/msdrakula/J.A.R.V.I.S/internal/httpclient"
	"github.com/msdrakula/J.A.R.V.I.S/internal/logger"
	"github.com/msdrakula/J.A.R.V.I.S/internal/modules/availability"
	"github.com/msdrakula/J.A.R.V.I.S/internal/modules/recon"
	"github.com/msdrakula/J.A.R.V.I.S/internal/modules/urlaudit"
	"github.com/msdrakula/J.A.R.V.I.S/internal/report"
	"github.com/msdrakula/J.A.R.V.I.S/internal/storage"
)

var (
	cfgPath string
	outputDir string
	verbose bool
	quiet bool
)

func Execute(ctx context.Context) error {
	root := &cobra.Command{Use: "jarvis", Short: "Safe internal audit CLI"}
	root.PersistentFlags().StringVarP(&cfgPath, "config", "c", "", "Path to config file")
	root.PersistentFlags().StringVarP(&outputDir, "output", "o", "", "Output directory")
	root.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Verbose logs")
	root.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "Quiet mode")

	root.AddCommand(newScanCmd())
	root.AddCommand(newReconCmd())
	root.AddCommand(newPortscanCmd())
	root.AddCommand(newDirbustCmd())
	root.AddCommand(newHistoryCmd())
	root.AddCommand(newShowCmd())
	root.AddCommand(newReportCmd())
	root.AddCommand(newQueryCmd())
	root.AddCommand(newDiffCmd())
	root.AddCommand(newResumeCmd())

	return root.ExecuteContext(ctx)
}

func loadRuntime() (*config.Config, *zap.Logger, *storage.Store, string, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, nil, nil, "", err
	}
	if cfg == nil {
		cfg = config.Defaults()
	}
	cfg.Normalize()

	if outputDir != "" {
		cfg.OutputDir = outputDir
	}
	if cfg.OutputDir == "" {
		cfg.OutputDir = "./results"
	}

	log, err := logger.New(verbose, quiet)
	if err != nil {
		return nil, nil, nil, "", err
	}
	if log == nil {
		log = zap.NewNop()
	}

	if err := os.MkdirAll(cfg.OutputDir, 0o755); err != nil {
		return nil, nil, nil, "", err
	}

	dbPath := filepath.Join(cfg.OutputDir, ".jarvis.db")
	store, err := storage.Open(dbPath)
	if err != nil {
		return nil, nil, nil, "", err
	}

	return cfg, log, store, dbPath, nil
}

func newScanID() string {
	buf := make([]byte, 8)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}

func createScan(store *storage.Store, target string, modules []string, output string) (string, error) {
	if store == nil {
		return "", fmt.Errorf("storage is not initialized")
	}
	id := newScanID()
	scan := storage.Scan{
		ID:         id,
		Target:     target,
		StartedAt:  time.Now().UTC().Format(time.RFC3339),
		FinishedAt: time.Now().UTC().Format(time.RFC3339),
		Modules:    strings.Join(modules, ","),
		Level:      1,
		Status:     "running",
		OutputPath: output,
	}
	return id, store.CreateScan(scan)
}

func loadWordlist(path string) ([]string, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	result := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		result = append(result, line)
	}
	return result, nil
}

func newReconCmd() *cobra.Command {
	var target string
	cmd := &cobra.Command{
		Use:   "recon",
		Short: "Collect safe configuration info",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, _, store, _, err := loadRuntime()
			if err != nil {
				return err
			}
			defer store.Close()

			client, err := httpclient.NewClient(cfg.HTTP)
			if err != nil {
				return err
			}

			scanID, err := createScan(store, target, []string{"recon"}, cfg.OutputDir)
			if err != nil {
				return err
			}

			auditor := recon.New(client, store)
			if _, err := auditor.ResolveDNS(scanID, target); err != nil {
				return err
			}
			if _, err := auditor.ReadTLS(scanID, target); err != nil {
				return err
			}
			if _, err := auditor.FetchRobots(scanID, "https://"+target); err != nil {
				return err
			}
			if _, err := auditor.FetchSitemap(scanID, "https://"+target); err != nil {
				return err
			}
			if _, err := auditor.ExtractFormParameters(scanID, "https://"+target); err != nil {
				return err
			}

			fmt.Println("Recon scan saved:", scanID)
			return nil
		},
	}
	cmd.Flags().StringVarP(&target, "url", "u", "", "Target domain")
	return cmd
}

func newPortscanCmd() *cobra.Command {
	var host string
	var ports []int
	cmd := &cobra.Command{
		Use:   "portscan",
		Short: "Check availability of listed services",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, _, store, _, err := loadRuntime()
			if err != nil {
				return err
			}
			defer store.Close()

			scanID, err := createScan(store, host, []string{"availability"}, "./results")
			if err != nil {
				return err
			}

			checker := availability.New(store)
			for _, port := range ports {
				result, err := checker.CheckTCP(scanID, host, port)
				if err != nil {
					return err
				}
				fmt.Printf("%s:%d %s %s\n", result.Host, result.Port, result.State, result.Service)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&host, "target", "t", "", "Target host")
	cmd.Flags().IntSliceVarP(&ports, "ports", "p", []int{22, 80, 443}, "Ports to check")
	return cmd
}

func newDirbustCmd() *cobra.Command {
	var baseURL string
	var paths []string
	var wordlist string
	cmd := &cobra.Command{
		Use:   "dirbust",
		Short: "Audit explicitly listed URL paths",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, _, store, _, err := loadRuntime()
			if err != nil {
				return err
			}
			defer store.Close()

			client, err := httpclient.NewClient(cfg.HTTP)
			if err != nil {
				return err
			}

			scanID, err := createScan(store, baseURL, []string{"urlaudit"}, cfg.OutputDir)
			if err != nil {
				return err
			}

			wordlistPaths, err := loadWordlist(wordlist)
			if err != nil {
				return err
			}
			allPaths := append(paths, wordlistPaths...)

			auditor := urlaudit.New(client, store)
			results, err := auditor.CheckPaths(scanID, baseURL, allPaths)
			if err != nil {
				return err
			}

			fmt.Print(urlaudit.VisualizeTree(results))
			return nil
		},
	}
	cmd.Flags().StringVarP(&baseURL, "url", "u", "", "Base URL")
	cmd.Flags().StringSliceVarP(&paths, "paths", "p", []string{}, "Explicit paths to check")
	cmd.Flags().StringVarP(&wordlist, "wordlist", "w", "", "Path to wordlist file")
	return cmd
}

func newShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show [scan_id]",
		Short: "Show scan details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, _, store, _, err := loadRuntime()
			if err != nil {
				return err
			}
			defer store.Close()

			scanRows, err := store.Query(args[0], "SELECT * FROM scans WHERE id = ?", args[0])
			if err != nil {
				return err
			}
			for _, row := range scanRows {
				fmt.Println("Scan:", row)
			}

			counts := []struct {
				label string
				query string
			}{
				{label: "DNS records", query: "SELECT COUNT(*) AS count FROM dns_records WHERE scan_id = ?"},
				{label: "TLS entries", query: "SELECT COUNT(*) AS count FROM tls_info WHERE scan_id = ?"},
				{label: "Service checks", query: "SELECT COUNT(*) AS count FROM service_availability WHERE scan_id = ?"},
				{label: "Paths", query: "SELECT COUNT(*) AS count FROM paths WHERE scan_id = ?"},
				{label: "Parameters", query: "SELECT COUNT(*) AS count FROM parameters WHERE scan_id = ?"},
				{label: "Findings", query: "SELECT COUNT(*) AS count FROM findings WHERE scan_id = ?"},
			}
			for _, item := range counts {
				rows, err := store.Query(args[0], item.query, args[0])
				if err != nil {
					return err
				}
				fmt.Printf("%s: %v\n", item.label, rows[0]["count"])
			}

			missingHeaders, err := store.Query(args[0], "SELECT name, url FROM findings WHERE scan_id = ? AND category = 'security-header'", args[0])
			if err != nil {
				return err
			}
			fmt.Println("Missing security headers:")
			for _, row := range missingHeaders {
				fmt.Printf("- %v at %v\n", row["name"], row["url"])
			}

			complianceFindings, err := store.Query(args[0], "SELECT name, url, evidence FROM findings WHERE scan_id = ? AND category = 'compliance'", args[0])
			if err != nil {
				return err
			}
			fmt.Println("Compliance findings:")
			for _, row := range complianceFindings {
				fmt.Printf("- %v at %v (%v)\n", row["name"], row["url"], row["evidence"])
			}

			pathRows, err := store.Query(args[0], "SELECT url, status_code FROM paths WHERE scan_id = ?", args[0])
			if err != nil {
				return err
			}
			if len(pathRows) > 0 {
				fmt.Println("Path tree:")
				fmt.Print(renderPathTree(pathRows))
			}

			return nil
		},
	}
}

func newReportCmd() *cobra.Command {
	var format string
	var output string
	cmd := &cobra.Command{
		Use:   "report [scan_id]",
		Short: "Generate simple report",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, _, store, _, err := loadRuntime()
			if err != nil {
				return err
			}
			defer store.Close()

			scanRows, err := store.Query(args[0], "SELECT * FROM scans WHERE id = ?", args[0])
			if err != nil {
				return err
			}

			if format == "nmap" {
				if len(scanRows) == 0 {
					return fmt.Errorf("scan not found")
				}
				if output == "" {
					output = filepath.Join("reports", args[0]+".xml")
				}
				return report.ExportToNmapXML(store, args[0], output)
			}

			if format == "csv" {
				if len(scanRows) == 0 {
					return fmt.Errorf("scan not found")
				}
				if output == "" {
					output = filepath.Join("reports", args[0]+".csv")
				}
				return report.ExportFindingsCSV(store, args[0], output)
			}

			if format == "html" {
				if len(scanRows) == 0 {
					return fmt.Errorf("scan not found")
				}

				scan := storage.Scan{
					ID:         fmt.Sprintf("%v", scanRows[0]["id"]),
					Target:     fmt.Sprintf("%v", scanRows[0]["target"]),
					StartedAt:  fmt.Sprintf("%v", scanRows[0]["started_at"]),
					FinishedAt: fmt.Sprintf("%v", scanRows[0]["finished_at"]),
					Modules:    fmt.Sprintf("%v", scanRows[0]["modules"]),
					Status:     fmt.Sprintf("%v", scanRows[0]["status"]),
					OutputPath: fmt.Sprintf("%v", scanRows[0]["output_path"]),
				}

				paths, err := store.Query(args[0], "SELECT url, status_code, size, content_type FROM paths WHERE scan_id = ?", args[0])
				if err != nil {
					return err
				}
				findings, err := store.Query(args[0], "SELECT severity, name, description, url, evidence FROM findings WHERE scan_id = ?", args[0])
				if err != nil {
					return err
				}

				if output == "" {
					output = filepath.Join("reports", args[0]+".html")
				}
				return report.GenerateHTML(output, scan, paths, findings)
			}

			var content string
			switch format {
			case "json":
				data, _ := json.MarshalIndent(scanRows, "", "  ")
				content = string(data)
			default:
				content = "# Report\n\n"
				for _, row := range scanRows {
					content += fmt.Sprintf("- %v\n", row)
				}
			}

			if output == "" {
				output = filepath.Join("reports", args[0]+"."+format)
			}
			if err := os.MkdirAll(filepath.Dir(output), 0o755); err != nil {
				return err
			}
			return os.WriteFile(output, []byte(content), 0o644)
		},
	}
	cmd.Flags().StringVar(&format, "format", "markdown", "Report format")
	cmd.Flags().StringVar(&output, "output", "", "Output file")
	return cmd
}

func newQueryCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "query [scan_id] [sql]",
		Short: "Run SQL query",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, _, store, _, err := loadRuntime()
			if err != nil {
				return err
			}
			defer store.Close()

			rows, err := store.Query(args[0], args[1])
			if err != nil {
				return err
			}
			for _, row := range rows {
				fmt.Println(row)
			}
			return nil
		},
	}
}
