package report

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"

	"github.com/msdrakula/J.A.R.V.I.S/internal/storage"
)

var csvHeader = []string{"scan_id", "timestamp", "severity", "category", "rule_id", "url", "description"}

// ExportFindingsCSV выгружает все findings скана в CSV, пригодный для Excel/BI.
func ExportFindingsCSV(store *storage.Store, scanID, outputPath string) error {
	rows, err := store.Query(scanID, `
		SELECT f.scan_id, s.started_at, f.severity, f.category, f.name, f.url, f.description
		FROM findings f
		LEFT JOIN scans s ON s.id = f.scan_id
		WHERE f.scan_id = ?
		ORDER BY f.severity, f.category`, scanID)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return err
	}

	file, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	if err := writer.Write(csvHeader); err != nil {
		return err
	}

	for _, row := range rows {
		record := []string{
			fmt.Sprintf("%v", row["scan_id"]),
			fmt.Sprintf("%v", row["started_at"]),
			fmt.Sprintf("%v", row["severity"]),
			fmt.Sprintf("%v", row["category"]),
			fmt.Sprintf("%v", row["name"]),
			fmt.Sprintf("%v", row["url"]),
			fmt.Sprintf("%v", row["description"]),
		}
		if err := writer.Write(record); err != nil {
			return err
		}
	}

	writer.Flush()
	return writer.Error()
}
