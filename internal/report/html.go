package report

import (
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/msdrakula/J.A.R.V.I.S/internal/storage"
)

type HTMLData struct {
	Title           string
	GeneratedAt     string
	Scan            storage.Scan
	Paths           []map[string]interface{}
	Findings        []map[string]interface{}
	TopFindings     []map[string]interface{}
	SeveritySummary map[string]int
	PathsCount      int
	FindingsCount   int
	Duration        string
}

func GenerateHTML(outputPath string, scan storage.Scan, paths []map[string]interface{}, findings []map[string]interface{}) error {
	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"severityClass": severityClass,
		"statusClass":   statusClass,
		"add":           func(a, b int) int { return a + b },
	}).Parse(htmlTemplate)
	if err != nil {
		return err
	}

	sortedFindings := append([]map[string]interface{}{}, findings...)
	sort.SliceStable(sortedFindings, func(i, j int) bool {
		return severityRank(asString(sortedFindings[i]["severity"])) < severityRank(asString(sortedFindings[j]["severity"]))
	})

	topFindings := sortedFindings
	if len(topFindings) > 10 {
		topFindings = topFindings[:10]
	}

	data := HTMLData{
		Title:           "JARVIS Safe Audit Report",
		GeneratedAt:     time.Now().Format(time.RFC3339),
		Scan:            scan,
		Paths:           paths,
		Findings:        findings,
		TopFindings:     topFindings,
		SeveritySummary: summarizeSeverity(findings),
		PathsCount:      len(paths),
		FindingsCount:   len(findings),
		Duration:        scanDuration(scan.StartedAt, scan.FinishedAt),
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

func asString(v interface{}) string {
	if v == nil {
		return ""
	}
	return strings.ToLower(fmt.Sprintf("%v", v))
}

func severityRank(severity string) int {
	switch severity {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	default:
		return 4
	}
}

func summarizeSeverity(findings []map[string]interface{}) map[string]int {
	summary := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
	for _, finding := range findings {
		severity := asString(finding["severity"])
		if severity == "" {
			severity = "info"
		}
		summary[severity]++
	}
	return summary
}

func scanDuration(startedAt string, finishedAt string) string {
	start, err1 := time.Parse(time.RFC3339, startedAt)
	finish, err2 := time.Parse(time.RFC3339, finishedAt)
	if err1 != nil || err2 != nil {
		return "unknown"
	}
	return finish.Sub(start).String()
}

func severityClass(severity interface{}) string {
	switch asString(severity) {
	case "critical", "high":
		return "sev-high"
	case "medium":
		return "sev-medium"
	case "low", "info":
		return "sev-low"
	default:
		return "sev-info"
	}
}

func statusClass(status interface{}) string {
	s := asString(status)
	switch {
	case strings.HasPrefix(s, "2"):
		return "status-ok"
	case strings.HasPrefix(s, "3"):
		return "status-redirect"
	case strings.HasPrefix(s, "4"), strings.HasPrefix(s, "5"):
		return "status-error"
	default:
		return "status-other"
	}
}

const htmlTemplate = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{{.Title}}</title>
<style>
body{font-family:Arial,sans-serif;margin:24px;background:#f7f7f9;color:#222}
.card{background:#fff;border:1px solid #ddd;border-radius:8px;padding:16px;margin-bottom:16px}
h1,h2{margin-top:0}
table{width:100%;border-collapse:collapse}
th,td{padding:8px;border-bottom:1px solid #ddd;text-align:left;vertical-align:top}
.small{font-size:12px;color:#666}
.summary{display:flex;gap:12px;flex-wrap:wrap}
.badge{padding:10px 12px;border-radius:6px;color:#fff;font-weight:bold}
.badge.high{background:#b00020}
.badge.medium{background:#b26a00}
.badge.low,.badge.info{background:#0b5fff}
.sev-high{color:#b00020;font-weight:bold}
.sev-medium{color:#b26a00;font-weight:bold}
.sev-low,.sev-info{color:#0b5fff;font-weight:bold}
.status-ok{color:#0b6b2f;font-weight:bold}
.status-redirect{color:#b26a00;font-weight:bold}
.status-error{color:#b00020;font-weight:bold}
.status-other{color:#555;font-weight:bold}
</style>
</head>
<body>
<div class="card">
  <h1>{{.Title}}</h1>
  <div class="small">Generated: {{.GeneratedAt}}</div>
  <p>Target: {{.Scan.Target}}</p>
  <p>Status: {{.Scan.Status}}</p>
  <p>Duration: {{.Duration}}</p>
</div>
<div class="card">
  <h2>Сводка</h2>
  <div class="summary">
    <div class="badge high">Critical/High: {{index .SeveritySummary "critical" | printf "%d"}}{{if gt (index .SeveritySummary "high") 0}} + {{index .SeveritySummary "high"}}{{end}}</div>
    <div class="badge medium">Medium: {{index .SeveritySummary "medium"}}</div>
    <div class="badge low">Low/Info: {{add (index .SeveritySummary "low") (index .SeveritySummary "info")}}</div>
  </div>
</div>
<div class="card">
  <h2>Статистика сканирования</h2>
  <p>Paths checked: {{.PathsCount}}</p>
  <p>Findings: {{.FindingsCount}}</p>
  <p>Duration: {{.Duration}}</p>
</div>
<div class="card">
  <h2>Топ-10 критичных находок</h2>
  <table>
    <tr><th>Severity</th><th>Rule ID</th><th>Description</th><th>URL</th></tr>
    {{range .TopFindings}}
    <tr>
      <td class="{{severityClass (index . "severity")}}">{{index . "severity"}}</td>
      <td>{{index . "name"}}</td>
      <td>{{index . "description"}}</td>
      <td>{{index . "url"}}</td>
    </tr>
    {{end}}
  </table>
</div>
<div class="card">
  <h2>Найденные пути</h2>
  <table>
    <tr><th>URL</th><th>Status Code</th><th>Size</th><th>Content-Type</th></tr>
    {{range .Paths}}
    <tr>
      <td>{{index . "url"}}</td>
      <td class="{{statusClass (index . "status_code")}}">{{index . "status_code"}}</td>
      <td>{{index . "size"}}</td>
      <td>{{index . "content_type"}}</td>
    </tr>
    {{end}}
  </table>
</div>
<div class="card">
  <h2>Все находки</h2>
  <table>
    <tr><th>Severity</th><th>Name</th><th>URL</th><th>Evidence</th></tr>
    {{range .Findings}}
    <tr>
      <td class="{{severityClass (index . "severity")}}">{{index . "severity"}}</td>
      <td>{{index . "name"}}</td>
      <td>{{index . "url"}}</td>
      <td>{{index . "evidence"}}</td>
    </tr>
    {{end}}
  </table>
</div>
</body>
</html>`
