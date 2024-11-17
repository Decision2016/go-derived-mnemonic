# Mnemonic derivation tool base on bip-85

bip-85: [Deterministic Entropy From BIP32 Keychains](https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki)

## Usage

compile the tool at first

```bash
git clone https://github.com/Decision2016/go-derived-mnemonic.git
cd ./go-derived-mnemonic/cmd/main
go build
```

generate new mnemonic:

```bash
./main new

create new mnemonic:
used legend breeze program soldier position toddler limb long dinosaur urge hunt
```

derive sub-mnemonics by master mnemonic:

```bash
./main derive -n 5 -l 12 -m "used legend breeze program soldier position toddler limb long dinosaur urge hunt"

derive 5 new mnemonics based on [m/83696968'/0'/0']:
find arch doctor life account above decide example pool brand space gym
fade miracle siege logic menu beach stick barely cry gauge pair thunder
oxygen slot return brick humble hunt hope skin season stadium attitude insane
shoulder lunar okay require arena rural close affair summer bunker trust tag
steel staff bird cable transfer eagle enough obvious faculty sad invest viable
```

## Helps

The options for derive mnemonic command: `./main derive -h`

Usage:
  mderive derive -m mnemonic [--path | -p] [--passphrase | -e] [--count | -n]  [flags]

Flags:

  -n, --count int           mnemonic derive count (default 1)
  
  -h, --help                help for derive
  
  -l, --length int          mnemonic length, must be 12, 15, 18, 21 or 24 (default 12)
  
  -m, --mnemonic string     mnemonic passphrase
  
  -e, --passphrase string   mnemonic need to be derived
  
  -p, --path string         base derive path (default "m/83696968'/0'/0'")
