package cli

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

func newHistoryCmd() *cobra.Command {
	var status string
	var limit int
	var since string

	cmd := &cobra.Command{
		Use:   "history",
		Short: "List saved scans with filters",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, _, store, _, err := loadRuntime()
			if err != nil {
				return err
			}
			defer store.Close()

			rows, err := store.Query("", `
				SELECT s.id, s.target, s.started_at, s.status,
				       COUNT(f.id) AS findings
				FROM scans s
				LEFT JOIN findings f ON f.scan_id = s.id
				GROUP BY s.id
				ORDER BY s.started_at DESC`)
			if err != nil {
				return err
			}

			var sinceTime time.Time
			if since != "" {
				t, err := parseSince(since)
				if err != nil {
					return fmt.Errorf("invalid --since value %q: %w", since, err)
				}
				sinceTime = t
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tTARGET\tDATE\tSTATUS\tFINDINGS")
			fmt.Fprintln(w, "────────\t──────\t────\t──────\t────────")

			shown := 0
			for _, row := range rows {
				if limit > 0 && shown >= limit {
					break
				}

				scanStatus := fmt.Sprintf("%v", row["status"])
				if status != "" && !strings.EqualFold(scanStatus, status) {
					continue
				}

				startedAt := fmt.Sprintf("%v", row["started_at"])
				if !sinceTime.IsZero() {
					parsed, err := time.Parse(time.RFC3339, startedAt)
					if err != nil || parsed.Before(sinceTime) {
						continue
					}
				}

				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%v\n",
					row["id"], row["target"], formatTimestamp(startedAt), scanStatus, row["findings"])
				shown++
			}

			if shown == 0 {
				fmt.Fprintln(w, "(no scans matched the filters)\t\t\t\t")
			}
			return w.Flush()
		},
	}

	cmd.Flags().StringVar(&status, "status", "", "Filter by status (completed, failed)")
	cmd.Flags().IntVar(&limit, "limit", 10, "Maximum number of scans to show (0 = all)")
	cmd.Flags().StringVar(&since, "since", "", "Only scans newer than (e.g. 24h, 7d)")
	return cmd
}

func parseSince(value string) (time.Time, error) {
	if strings.HasSuffix(value, "d") {
		days, err := strconv.Atoi(strings.TrimSuffix(value, "d"))
		if err != nil {
			return time.Time{}, err
		}
		return time.Now().Add(-time.Duration(days) * 24 * time.Hour), nil
	}
	d, err := time.ParseDuration(value)
	if err != nil {
		return time.Time{}, err
	}
	return time.Now().Add(-d), nil
}

func formatTimestamp(raw string) string {
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return raw
	}
	return t.Local().Format("2006-01-02 15:04")
}
