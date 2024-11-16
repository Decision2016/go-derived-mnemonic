package main

import "github.com/spf13/cobra"

var rootCmd = &cobra.Command{
	Use:   "mderive",
	Short: "M-Derive is a derivation tool to manage multiple mnemonic.",
	Long:  "M-Derive is a derivation tool to manage multiple mnemonic.",
}

func main() {
	rootCmd.Execute()
}
