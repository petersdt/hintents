package cmd

import (
	"fmt"

	"github.com/dotandev/hintents/internal/db"
	"github.com/spf13/cobra"
)

var (
	searchErrorFlag string
	searchEventFlag string
	searchTxFlag    string
	searchLimitFlag int
)

var searchCmd = &cobra.Command{
	Use:   "search",
	Short: "Search past debugging sessions",
	Long: `Search through the history of debugging sessions using regex patterns 
for errors or events, or by specific transaction hash.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		store, err := db.InitDB()
		if err != nil {
			return fmt.Errorf("failed to initialize database: %w", err)
		}

		params := db.SearchParams{
			TxHash:     searchTxFlag,
			ErrorRegex: searchErrorFlag,
			EventRegex: searchEventFlag,
			Limit:      searchLimitFlag,
		}

		sessions, err := store.SearchSessions(params)
		if err != nil {
			return fmt.Errorf("search failed: %w", err)
		}

		if len(sessions) == 0 {
			fmt.Println("No matching sessions found.")
			return nil
		}

		fmt.Printf("Found %d matching sessions:\n", len(sessions))
		for _, s := range sessions {
			fmt.Println("--------------------------------------------------")
			fmt.Printf("ID: %d\n", s.ID)
			fmt.Printf("Time: %s\n", s.Timestamp.Format("2006-01-02 15:04:05"))
			fmt.Printf("Tx Hash: %s\n", s.TxHash)
			fmt.Printf("Network: %s\n", s.Network)
			fmt.Printf("Status: %s\n", s.Status)
			if s.ErrorMsg != "" {
				fmt.Printf("Error: %s\n", s.ErrorMsg)
			}
			if len(s.Events) > 0 {
				fmt.Println("Events:")
				for _, e := range s.Events {
					fmt.Printf("  - %s\n", e)
				}
			}
		}
		fmt.Println("--------------------------------------------------")

		return nil
	},
}

func init() {
	searchCmd.Flags().StringVar(&searchErrorFlag, "error", "", "Regex pattern to match error messages")
	searchCmd.Flags().StringVar(&searchEventFlag, "event", "", "Regex pattern to match events")
	searchCmd.Flags().StringVar(&searchTxFlag, "tx", "", "Transaction hash to search for")
	searchCmd.Flags().IntVar(&searchLimitFlag, "limit", 10, "Maximum number of results to return")

	rootCmd.AddCommand(searchCmd)
}
