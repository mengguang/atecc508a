package main

import (
	"strings"
	"fmt"
	"encoding/hex"
	"math/big"
	"crypto/ecdsa"
	"crypto/elliptic"
)

func Verify(pubKey string, data string, signature string) bool {

	bytePubKey := make([]byte,hex.DecodedLen(len(pubKey)))
	byteSignature := make([]byte,hex.DecodedLen(len(signature)))
	byteData := make([]byte,hex.DecodedLen(len(data)))

	hex.Decode(bytePubKey,[]byte(pubKey))
	hex.Decode(byteSignature,[]byte(signature))
	hex.Decode(byteData,[]byte(data))

	//fmt.Println(bytePubKey)
	//fmt.Println(byteData)
	//fmt.Println(byteSignature)

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
	if ecdsa.Verify(&realPubKey, byteData, &r, &s) == false {
		return false
	} else {
		return true
	}
}

func main() {

	hexPubKeyWithSpace := "FC BC 2D 00 06 81 C5 FA 20 AF 21 05 27 79 6E 65 7E 59 A6 7A FC 13 33 91 D3 EB 0F 2E F2 37 28 F9 FD B6 37 85 43 76 E1 06 6B BF B2 A9 97 88 CE 4A 20 D8 49 85 B3 28 E8 97 DC 30 8F 74 32 C8 E2 88"
	hexPubKey := strings.Replace(hexPubKeyWithSpace," ","",-1)
	fmt.Println("public key:", hexPubKey)

	hexData := "5a3c2eaf06b803d29f79520aa373ca40200ab1ad622c1a2022a63af1a6054988"
	hexData = strings.ToUpper(hexData)
	fmt.Println("data:",hexData)

	hexSignWithSpace := "03 E5 52 6E DC 27 0C B1 95 51 75 0B 83 0D 57 4F 5B 7E E6 3A DF A6 40 CC DD 68 4D F8 3C 60 0F 1B D0 90 A3 69 41 8E E2 EB E1 18 23 90 88 74 2B 0C 89 89 4B 31 9D 1E 2C DA 16 89 62 08 FD EE 0B 20"
	hexSign := strings.Replace(hexSignWithSpace," ","",-1)
	fmt.Println("signature:",hexSign)

	result := Verify(hexPubKey,hexData,hexSign)
	fmt.Println("verify result:",result)

}
