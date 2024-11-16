package main

import "github.com/spf13/cobra"

var (
	newPassphrase string
)

var newMnemonic = &cobra.Command{
	Use:   "new [-p | --passphrase]",
	Short: "generate new mnemonic",
	Long:  "generate new mnemonic",
}

var deriveMnemonic = &cobra.Command{
	Use:   "derive",
	Short: "derive new mnemonics by main mnemonic",
	Long:  "derive new mnemonics by main mnemonic",
}
