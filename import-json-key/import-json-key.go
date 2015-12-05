package main

import (
	"crypto/rsa"
	"encoding/json"
	"encoding/pem"
	"flag"
	"github.com/stbuehler/go-acme-client/utils"
	"math/big"
	"os"
)

type JsonKey struct {
	D   string
	Dp  string
	Dq  string
	N   string
	E   string
	Qi  string
	Q   string
	Kty string
	P   string
}

func to_number(s string) *big.Int {
	var b big.Int
	if raw, err := utils.Base64UrlDecode(s); nil != err {
		utils.Fatalf("Couldn't parse big integer base64 %#v: %v", s, err)
		return nil
	} else {
		b.SetBytes(raw)
		return &b
	}
}

func show_privkey(k interface{}) {
	if block, err := utils.EncodePrivateKey(k); nil != err {
		utils.Fatalf("Couldn't encode private key: %v", err)
	} else if err := pem.Encode(os.Stdout, block); nil != err {
		utils.Fatalf("Couldn't write private key: %v", err)
	}
}

func show_pubkey(k interface{}) {
	if block, err := utils.EncodePrivateKey(k); nil != err {
		utils.Fatalf("Couldn't encode public key: %v", err)
	} else if err := pem.Encode(os.Stdout, block); nil != err {
		utils.Fatalf("Couldn't write public key: %v", err)
	}
}

func input_file() *os.File {
	if 0 != len(flag.Arg(0)) {
		if file, err := os.Open(flag.Arg(0)); nil != err {
			utils.Fatalf("Couldn't open input file %#v: %v", flag.Arg(0), err)
			return nil
		} else {
			return file
		}
	} else {
		return os.Stdin
	}
}

func main() {
	var jk JsonKey

	if err := json.NewDecoder(input_file()).Decode(&jk); nil != err {
		utils.Fatalf("Couldn't parse input JSON file: %v", err)
	} else {
		switch jk.Kty {
		case "RSA":
			if 0 != len(jk.D) {
				var k rsa.PrivateKey
				k.E = int(to_number(jk.E).Int64())
				k.N = to_number(jk.N)
				k.D = to_number(jk.D)
				k.Primes = []*big.Int{to_number(jk.P), to_number(jk.Q)}
				show_privkey(&k)
			} else {
				var k rsa.PublicKey
				k.E = int(to_number(jk.E).Int64())
				k.N = to_number(jk.N)
				show_pubkey(&k)
			}
		default:
			utils.Fatalf("keytype %#v not supported", jk.Kty)
		}
	}
}
