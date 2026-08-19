package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/msdrakula/J.A.R.V.I.S/internal/httpclient"
	"github.com/msdrakula/J.A.R.V.I.S/internal/modules/urlaudit"
)

// newResumeCmd возобновляет прерванный скан: догоняет только те пути из
// инвентаря, которых ещё нет в таблице paths для данного scan_id.
func newResumeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "resume [scan_id]",
		Short: "Resume an interrupted scan",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, _, store, _, err := loadRuntime()
			if err != nil {
				return err
			}
			defer store.Close()

			scanID := args[0]
			rows, err := store.Query(scanID, "SELECT status FROM scans WHERE id = ?", scanID)
			if err != nil {
				return err
			}
			if len(rows) == 0 {
				return fmt.Errorf("scan %q not found", scanID)
			}

			status := fmt.Sprintf("%v", rows[0]["status"])
			if status == "completed" {
				fmt.Println("Scan already completed, nothing to resume")
				return nil
			}

			checked, err := store.GetCheckedURLs(scanID)
			if err != nil {
				return err
			}

			client, err := httpclient.NewClient(cfg.HTTP)
			if err != nil {
				return err
			}

			auditor := urlaudit.New(client, store)
			resumed := 0

			for _, target := range cfg.Inventory.URLs {
				remaining := []string{}
				for _, path := range target.Paths {
					fullURL := strings.TrimRight(target.Base, "/") + "/" + strings.TrimLeft(path, "/")
					if !checked[fullURL] {
						remaining = append(remaining, path)
					}
				}
				if len(remaining) == 0 {
					continue
				}
				if _, err := auditor.CheckPaths(scanID, target.Base, remaining); err != nil {
					return err
				}
				resumed += len(remaining)
			}

			if err := store.UpdateScanStatus(scanID, "completed"); err != nil {
				return err
			}
			fmt.Printf("Scan %s resumed: %d remaining paths checked, status set to completed\n", scanID, resumed)
			return nil
		},
	}
}
