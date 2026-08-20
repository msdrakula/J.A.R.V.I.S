package cli

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/msdrakula/J.A.R.V.I.S/internal/storage"
)

func printScanSummary(store *storage.Store, scanID, target, dbPath string, warnings []string) {
	fmt.Println()
	fmt.Println("════════════════════════════════════════════════════")
	fmt.Printf("  JARVIS  scan_id=%s\n", scanID)
	fmt.Printf("  Target  %s\n", target)
	if len(warnings) > 0 {
		fmt.Printf("  Status  completed with %d warning(s)\n", len(warnings))
	} else {
		fmt.Println("  Status  completed")
	}
	fmt.Println("════════════════════════════════════════════════════")

	if store == nil {
		return
	}

	printOpenPorts(store, scanID)
	printDiscoveredPaths(store, scanID)
	printFindingsSummary(store, scanID)

	if len(warnings) > 0 {
		fmt.Println()
		fmt.Println("WARNINGS")
		for _, item := range warnings {
			fmt.Printf("  • %s\n", item)
		}
	}

	outDir := outputDirOrDot(dbPath)
	fmt.Println()
	fmt.Println("NEXT")
	fmt.Printf("  ./jarvis show %s -o %s\n", scanID, outDir)
	fmt.Printf("  ./jarvis report %s --format html --output dashboard.html -o %s\n", scanID, outDir)
	fmt.Println()
	fmt.Println("  .jarvis.db is a SQLite database. Do not cat it.")
	fmt.Println()
}

func outputDirOrDot(dbPath string) string {
	if dbPath == "" {
		return "./results"
	}
	dir := strings.TrimSuffix(dbPath, "/.jarvis.db")
	dir = strings.TrimSuffix(dir, "\\.jarvis.db")
	if dir == "" || dir == dbPath {
		return "./results"
	}
	return dir
}

func printOpenPorts(store *storage.Store, scanID string) {
	rows, err := store.Query(scanID, `
		SELECT host, port, state, service
		FROM service_availability
		WHERE scan_id = ?
		ORDER BY port`, scanID)
	if err != nil || len(rows) == 0 {
		return
	}
	fmt.Println()
	fmt.Println("PORTS")
	for _, row := range rows {
		state := strings.ToUpper(fmt.Sprintf("%v", row["state"]))
		fmt.Printf("  %s:%v  %-6s  %v\n", row["host"], row["port"], state, row["service"])
	}
}

func printDiscoveredPaths(store *storage.Store, scanID string) {
	rows, err := store.Query(scanID, `
		SELECT DISTINCT url, status_code, content_type
		FROM paths
		WHERE scan_id = ?
		ORDER BY url`, scanID)
	if err != nil || len(rows) == 0 {
		return
	}

	fmt.Println()
	fmt.Println("PATHS")
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	for _, row := range rows {
		status := parseIntValue(row["status_code"])
		rawURL := fmt.Sprintf("%v", row["url"])
		ctype := fmt.Sprintf("%v", row["content_type"])
		if i := strings.Index(ctype, ";"); i >= 0 {
			ctype = ctype[:i]
		}
		mark := interestingMark(status, rawURL)
		fmt.Fprintf(w, "  %s\t%s\t%s\t%s\n",
			colorizeStatus(status, fmt.Sprintf("[%d]", status)),
			rawURL,
			ctype,
			mark,
		)
	}
	_ = w.Flush()

	fmt.Println()
	fmt.Println("PATH TREE")
	fmt.Print(renderPathTree(rows))
}

func printFindingsSummary(store *storage.Store, scanID string) {
	rows, err := store.Query(scanID, `
		SELECT severity, category, name, url, description, evidence
		FROM findings
		WHERE scan_id = ?
		ORDER BY CASE lower(severity)
			WHEN 'critical' THEN 1
			WHEN 'high' THEN 2
			WHEN 'medium' THEN 3
			WHEN 'low' THEN 4
			ELSE 5
		END, category, name`, scanID)
	if err != nil || len(rows) == 0 {
		fmt.Println()
		fmt.Println("FINDINGS")
		fmt.Println("  (none)")
		return
	}

	headerGroups := map[string][]string{}
	var other []map[string]interface{}
	counts := map[string]int{}

	for _, row := range rows {
		sev := strings.ToLower(fmt.Sprintf("%v", row["severity"]))
		counts[sev]++
		if fmt.Sprintf("%v", row["category"]) == "security-header" {
			name := fmt.Sprintf("%v", row["name"])
			url := fmt.Sprintf("%v", row["url"])
			headerGroups[name] = append(headerGroups[name], url)
			continue
		}
		other = append(other, row)
	}

	fmt.Println()
	fmt.Println("FINDINGS")
	fmt.Printf("  high=%d  medium=%d  low=%d  info=%d\n",
		counts["high"], counts["medium"], counts["low"], counts["info"])

	if len(other) > 0 {
		fmt.Println()
		fmt.Println("  Interesting")
		for _, row := range other {
			sev := strings.ToUpper(fmt.Sprintf("%v", row["severity"]))
			fmt.Printf("  [%s] %v\n", sev, row["name"])
			fmt.Printf("         %v\n", row["url"])
			if ev := strings.TrimSpace(fmt.Sprintf("%v", row["evidence"])); ev != "" && ev != "<nil>" {
				fmt.Printf("         %s\n", ev)
			}
		}
	}

	if len(headerGroups) == 0 {
		return
	}
	fmt.Println()
	fmt.Println("  Missing security headers (grouped)")
	names := make([]string, 0, len(headerGroups))
	for name := range headerGroups {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		urls := uniqueStrings(headerGroups[name])
		fmt.Printf("  • %s  (%d URLs)\n", name, len(urls))
	}
}

func interestingMark(status int, rawURL string) string {
	lower := strings.ToLower(rawURL)
	switch {
	case strings.Contains(lower, ".env") || strings.Contains(lower, "backup") || strings.Contains(lower, "admin"):
		return "← look"
	case status == 200:
		return "ok"
	case status == 401 || status == 403:
		return "auth"
	case status >= 300 && status < 400:
		return "redirect"
	default:
		return ""
	}
}

func uniqueStrings(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
