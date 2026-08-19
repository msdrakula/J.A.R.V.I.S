package cli

import (
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

type findingKey struct {
	Name     string
	URL      string
	Severity string
}

func newDiffCmd() *cobra.Command {
	var format string
	var output string

	cmd := &cobra.Command{
		Use:   "diff [scan_id1] [scan_id2]",
		Short: "Compare two safe audit scans",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, _, store, _, err := loadRuntime()
			if err != nil {
				return err
			}
			defer store.Close()

			first, err := store.Query(args[0], "SELECT severity, name, url, description FROM findings WHERE scan_id = ?", args[0])
			if err != nil {
				return err
			}
			second, err := store.Query(args[1], "SELECT severity, name, url, description FROM findings WHERE scan_id = ?", args[1])
			if err != nil {
				return err
			}

			firstSet := map[findingKey]map[string]interface{}{}
			secondSet := map[findingKey]map[string]interface{}{}

			for _, row := range first {
				firstSet[makeFindingKey(row)] = row
			}
			for _, row := range second {
				secondSet[makeFindingKey(row)] = row
			}

			added := []map[string]interface{}{}
			removed := []map[string]interface{}{}
			unchanged := []map[string]interface{}{}

			for key, row := range secondSet {
				if _, ok := firstSet[key]; ok {
					unchanged = append(unchanged, row)
				} else {
					added = append(added, row)
				}
			}
			for key, row := range firstSet {
				if _, ok := secondSet[key]; !ok {
					removed = append(removed, row)
				}
			}

			sortDiffRows(added)
			sortDiffRows(removed)
			sortDiffRows(unchanged)

			if format == "html" {
				if output == "" {
					output = filepath.Join("reports", fmt.Sprintf("diff_%s_%s.html", args[0], args[1]))
				}
				return exportDiffHTML(output, args[0], args[1], added, removed, unchanged)
			}

			printDiffSection("New findings", added)
			printDiffSection("Resolved findings", removed)
			printDiffSection("Unchanged findings", unchanged)
			return nil
		},
	}

	cmd.Flags().StringVar(&format, "format", "text", "Output format: text or html")
	cmd.Flags().StringVar(&output, "output", "", "Output file for html format")
	return cmd
}

func makeFindingKey(row map[string]interface{}) findingKey {
	return findingKey{
		Name:     strings.ToLower(fmt.Sprintf("%v", row["name"])),
		URL:      strings.ToLower(fmt.Sprintf("%v", row["url"])),
		Severity: strings.ToLower(fmt.Sprintf("%v", row["severity"])),
	}
}

func sortDiffRows(rows []map[string]interface{}) {
	sort.Slice(rows, func(i, j int) bool {
		return fmt.Sprintf("%v", rows[i]["name"]) < fmt.Sprintf("%v", rows[j]["name"])
	})
}

func printDiffSection(title string, rows []map[string]interface{}) {
	fmt.Println(title + ":")
	if len(rows) == 0 {
		fmt.Println("- none")
		return
	}
	for _, row := range rows {
		fmt.Printf("- [%v] %v at %v\n", row["severity"], row["name"], row["url"])
	}
}

type diffHTMLData struct {
	ScanA       string
	ScanB       string
	GeneratedAt string
	Added       []map[string]interface{}
	Removed     []map[string]interface{}
	Unchanged   []map[string]interface{}
}

func exportDiffHTML(outputPath, scanA, scanB string, added, removed, unchanged []map[string]interface{}) error {
	tmpl, err := template.New("diff").Parse(diffHTMLTemplate)
	if err != nil {
		return err
	}

	data := diffHTMLData{
		ScanA:       scanA,
		ScanB:       scanB,
		GeneratedAt: time.Now().Format(time.RFC3339),
		Added:       added,
		Removed:     removed,
		Unchanged:   unchanged,
	}

	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return err
	}

	file, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer file.Close()

	return tmpl.Execute(file, data)
}

const diffHTMLTemplate = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>JARVIS Diff Report</title>
<style>
body{font-family:Arial,sans-serif;margin:24px;background:#f7f7f9;color:#222}
.card{background:#fff;border:1px solid #ddd;border-radius:8px;padding:16px;margin-bottom:16px}
h1,h2{margin-top:0}
table{width:100%;border-collapse:collapse}
th,td{padding:8px;border-bottom:1px solid #ddd;text-align:left;vertical-align:top}
.small{font-size:12px;color:#666}
.added{color:#b00020;font-weight:bold}
.removed{color:#0b6b2f;font-weight:bold}
.unchanged{color:#555}
</style>
</head>
<body>
<div class="card">
  <h1>JARVIS Diff Report</h1>
  <div class="small">Generated: {{.GeneratedAt}}</div>
  <p>Baseline: {{.ScanA}} → Compared: {{.ScanB}}</p>
</div>
<div class="card">
  <h2 class="added">New findings ({{len .Added}})</h2>
  <table>
    <tr><th>Severity</th><th>Name</th><th>URL</th></tr>
    {{range .Added}}<tr><td>{{index . "severity"}}</td><td>{{index . "name"}}</td><td>{{index . "url"}}</td></tr>{{end}}
  </table>
</div>
<div class="card">
  <h2 class="removed">Resolved findings ({{len .Removed}})</h2>
  <table>
    <tr><th>Severity</th><th>Name</th><th>URL</th></tr>
    {{range .Removed}}<tr><td>{{index . "severity"}}</td><td>{{index . "name"}}</td><td>{{index . "url"}}</td></tr>{{end}}
  </table>
</div>
<div class="card">
  <h2 class="unchanged">Unchanged findings ({{len .Unchanged}})</h2>
  <table>
    <tr><th>Severity</th><th>Name</th><th>URL</th></tr>
    {{range .Unchanged}}<tr><td>{{index . "severity"}}</td><td>{{index . "name"}}</td><td>{{index . "url"}}</td></tr>{{end}}
  </table>
</div>
</body>
</html>`
