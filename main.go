package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"flag"
	"fmt"
	"math/big"
	"strings"
)

func Verify(pubKey string, data string, signature string) bool {

	bytePubKey := make([]byte, hex.DecodedLen(len(pubKey)))
	byteSignature := make([]byte, hex.DecodedLen(len(signature)))
	byteData := make([]byte, hex.DecodedLen(len(data)))

	hex.Decode(bytePubKey, []byte(pubKey))
	hex.Decode(byteSignature, []byte(signature))
	hex.Decode(byteData, []byte(data))

	r := big.Int{}
	s := big.Int{}
	sigLen := len(byteSignature)
	r.SetBytes(byteSignature[:(sigLen / 2)])
	s.SetBytes(byteSignature[(sigLen / 2):])

	x := big.Int{}
	y := big.Int{}
	keyLen := len(bytePubKey)
	x.SetBytes(bytePubKey[:(keyLen / 2)])
	y.SetBytes(bytePubKey[(keyLen / 2):])

	curve := elliptic.P256()
	realPubKey := ecdsa.PublicKey{Curve: curve, X: &x, Y: &y}
	return ecdsa.Verify(&realPubKey, byteData, &r, &s)
}

func main() {
	var hexPubKey string
	flag.StringVar(&hexPubKey, "hexPubKey", "", "Public Key in HEX format.")
	var hexData string
	flag.StringVar(&hexData, "hexData", "", "Data in HEX format.")
	var hexSign string
	flag.StringVar(&hexSign, "hexSign", "", "Signature in HEX format.")
	flag.Parse()

	if len(hexPubKey) < 128 {
		fmt.Println("Invalid Public Key.")
		flag.PrintDefaults()
		return
	}
	if len(hexData) < 64 {
		fmt.Println("Invalid Data.")
		flag.PrintDefaults()
		return
	}
	if len(hexSign) < 128 {
		fmt.Println("Invalid Signature.")
		flag.PrintDefaults()
		return
	}

	hexPubKey = strings.Replace(hexPubKey, " ", "", -1)
	hexPubKey = strings.Replace(hexPubKey, "0x", "", -1)
	hexPubKey = strings.ToUpper(hexPubKey)
	fmt.Println("public key:", hexPubKey)

	hexData = strings.Replace(hexData, " ", "", -1)
	hexData = strings.Replace(hexData, "0x", "", -1)
	hexData = strings.ToUpper(hexData)
	fmt.Println("data:", hexData)

	hexSign = strings.Replace(hexSign, " ", "", -1)
	hexSign = strings.Replace(hexSign, "0x", "", -1)
	hexSign = strings.ToUpper(hexSign)
	fmt.Println("signature:", hexSign)

	result := Verify(hexPubKey, hexData, hexSign)
	fmt.Println("verify result:", result)

}
