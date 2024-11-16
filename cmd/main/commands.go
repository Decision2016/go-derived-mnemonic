package main

import (
	"fmt"
	"github.com/spf13/cobra"
	mderive "github.io/decision2016/go-derived-mnemonic"
)

var (
	length int

	deriveMnemonicLength int
	deriveMnemonic       string
	derivePassphrase     string
	deriveBasePath       string
	deriveCount          int
)

var generate = &cobra.Command{
	Use:   "new [--length | -l]",
	Short: "generate new mnemonic",
	Long:  "generate new mnemonic",
	Run: func(cmd *cobra.Command, args []string) {
		mnemonic, err := mderive.NewMnemonic(length)
		if err != nil {
			fmt.Printf("create new mnemonic failed: %s\n", err)
			return
		}

		fmt.Println("create new mnemonic:")
		fmt.Println(mnemonic)
	},
}

var derive = &cobra.Command{
	Use:   "derive -m mnemonic [--path | -p] [--passphrase | -e] [--count | -n] ",
	Short: "derive new mnemonics by main mnemonic",
	Long:  "derive new mnemonics by main mnemonic",
	Run: func(cmd *cobra.Command, args []string) {
		if !mderive.CheckInArr([]int{12, 15, 18, 21, 24}, deriveMnemonicLength) {
			fmt.Println("input wrong mnemonic length")
			return
		}

		seed, err := mderive.NewSeedWithErrorCheck(deriveMnemonic, derivePassphrase)
		if err != nil {
			fmt.Printf("decode mnemonic to seed failed: %s\n", err)
			return
		}

		master, err := mderive.NewMasterKey(seed)
		if err != nil {
			fmt.Printf("decode seed to master key failed: %s\n", err)
			return
		}

		basePath := deriveBasePath
		results := make([]string, deriveCount)
		bitsLength := deriveMnemonicLength*11 - deriveMnemonicLength/3

		for idx := 0; idx < deriveCount; idx++ {
			path := fmt.Sprintf("%s/%d", basePath, idx)
			entropy, err := mderive.DeriveEntropyForMnemonic(master, path)
			if err != nil {
				fmt.Printf("derive entropy for mnemonic failed: %s", err)
				return
			}

			derivedMnemonic, err := mderive.NewMnemonicByEntropy(entropy[:bitsLength/8])
			if err != nil {
				fmt.Printf("generate new mnemonic failed: %s", err)
				return
			}

			results[idx] = derivedMnemonic
		}

		fmt.Printf("derive %d new mnemonics based on path [%s]:\n", deriveCount, deriveBasePath)
		for idx := 0; idx < deriveCount; idx++ {
			fmt.Println(results[idx])
		}
	},
}

func init() {
	generate.Flags().IntVarP(&length, "length", "l", 12, "mnemonic length, must be 12, 15, 18, 21 or 24")

	derive.Flags().IntVarP(&deriveMnemonicLength, "length", "l", 12, "mnemonic length, must be 12, 15, 18, 21 or 24")
	derive.Flags().StringVarP(&derivePassphrase, "passphrase", "e", "", "mnemonic need to be derived")
	derive.Flags().StringVarP(&deriveMnemonic, "mnemonic", "m", "", "mnemonic passphrase")
	derive.Flags().StringVarP(&deriveBasePath, "path", "p", "m/83696968'/0'/0'", "base derive path")
	derive.Flags().IntVarP(&deriveCount, "count", "n", 1, "mnemonic derive count")

	rootCmd.AddCommand(generate)
	rootCmd.AddCommand(derive)
}
