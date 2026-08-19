package report

import (
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/msdrakula/J.A.R.V.I.S/internal/storage"
)

type NmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Scanner string     `xml:"scanner,attr"`
	Start   int64      `xml:"start,attr"`
	Version string     `xml:"version,attr"`
	Hosts   []NmapHost `xml:"host"`
}

type NmapHost struct {
	Address    NmapAddress   `xml:"address"`
	Ports      []NmapPort    `xml:"ports>port"`
	HostScript []NmapScript  `xml:"hostscript>script,omitempty"`
}

type NmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type NmapPort struct {
	Protocol string      `xml:"protocol,attr"`
	PortID   int         `xml:"portid,attr"`
	State    NmapState   `xml:"state"`
	Service  NmapService `xml:"service,omitempty"`
}

type NmapState struct {
	State string `xml:"state,attr"`
}

type NmapService struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr,omitempty"`
}

type NmapScript struct {
	ID     string `xml:"id,attr"`
	Output string `xml:"output,attr"`
}

func ExportToNmapXML(store *storage.Store, scanID, outputPath string) error {
	scanRows, err := store.Query(scanID, "SELECT * FROM scans WHERE id = ?", scanID)
	if err != nil {
		return err
	}
	if len(scanRows) == 0 {
		return fmt.Errorf("scan %q not found", scanID)
	}

	start := time.Now().Unix()
	if raw := fmt.Sprintf("%v", scanRows[0]["started_at"]); raw != "" {
		if t, err := time.Parse(time.RFC3339, raw); err == nil {
			start = t.Unix()
		}
	}

	portRows, err := store.Query(scanID, "SELECT host, port, state, service, banner FROM service_availability WHERE scan_id = ?", scanID)
	if err != nil {
		return err
	}
	findingRows, err := store.Query(scanID, "SELECT name, severity, url FROM findings WHERE scan_id = ?", scanID)
	if err != nil {
		return err
	}

	hosts := map[string]*NmapHost{}
	order := []string{}

	getHost := func(host string) *NmapHost {
		if h, ok := hosts[host]; ok {
			return h
		}
		addrType := "hostname"
		if isIP(host) {
			addrType = "ipv4"
		}
		h := &NmapHost{Address: NmapAddress{Addr: host, AddrType: addrType}}
		hosts[host] = h
		order = append(order, host)
		return h
	}

	for _, row := range portRows {
		host := fmt.Sprintf("%v", row["host"])
		h := getHost(host)
		h.Ports = append(h.Ports, NmapPort{
			Protocol: "tcp",
			PortID:   parseInt(row["port"]),
			State:    NmapState{State: fmt.Sprintf("%v", row["state"])},
			Service:  NmapService{Name: fmt.Sprintf("%v", row["service"])},
		})
	}

	for _, row := range findingRows {
		host := hostFromURL(fmt.Sprintf("%v", row["url"]))
		if host == "" {
			host = fmt.Sprintf("%v", scanRows[0]["target"])
		}
		h := getHost(host)
		h.HostScript = append(h.HostScript, NmapScript{
			ID:     "jarvis-finding",
			Output: fmt.Sprintf("%v: %v severity", row["name"], row["severity"]),
		})
	}

	run := NmapRun{
		Scanner: "jarvis",
		Start:   start,
		Version: "1.0",
		Hosts:   []NmapHost{},
	}
	for _, host := range order {
		run.Hosts = append(run.Hosts, *hosts[host])
	}

	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return err
	}

	file, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := file.WriteString(xml.Header); err != nil {
		return err
	}
	encoder := xml.NewEncoder(file)
	encoder.Indent("", "  ")
	if err := encoder.Encode(run); err != nil {
		return err
	}
	return encoder.Flush()
}

func isIP(host string) bool {
	for _, r := range host {
		if r != '.' && (r < '0' || r > '9') {
			return false
		}
	}
	return strings.Count(host, ".") == 3
}

func hostFromURL(rawURL string) string {
	trimmed := strings.TrimPrefix(rawURL, "https://")
	trimmed = strings.TrimPrefix(trimmed, "http://")
	if idx := strings.Index(trimmed, "/"); idx >= 0 {
		trimmed = trimmed[:idx]
	}
	return trimmed
}

func parseInt(v interface{}) int {
	switch t := v.(type) {
	case int64:
		return int(t)
	case int:
		return t
	case float64:
		return int(t)
	case string:
		var n int
		_, _ = fmt.Sscanf(t, "%d", &n)
		return n
	default:
		return 0
	}
}
