package main

import (
	"bytes"
	"fmt"
	"log"

	ecies "github.com/ecies/go"
	"github.com/ma2b0043/cvs"
)

func main() {
	fmt.Print("testing")
	//Generating Public and Private Key using a public implementation of secp256k1
	xPrivateKey, err := ecies.GenerateKey()
	if err != nil {
		panic(err)
	}
	log.Println("key pair has been generated")

	log.Println("Public Key:", xPrivateKey.PublicKey)
	log.Println("Private key:", xPrivateKey)

	log.Println("||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||")

	log.Print("Private key in hexadecimal: ", xPrivateKey.Hex())
	log.Print("Public key in hexadecimal: ", xPrivateKey.PublicKey.Hex(true))
	var PrivKey string = string(xPrivateKey.Hex())
	var PubKey string = string(xPrivateKey.PublicKey.Hex(true))
	log.Println("Private key in hexa now in string: ", PrivKey)
	log.Println("Public key in hexa now in string: ", PubKey)

	//encrypting a plain text with public key
	secert := "my name is sasuke uchiha."
	encryptedText, err1 := ecies.Encrypt(xPrivateKey.PublicKey, []byte(secert))
	if err1 != nil {
		log.Fatal("Error encrypting text: ", err1)
	}
	log.Printf("Encrypted text in hexa: %x\n", encryptedText)
	log.Println("||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||")

	//decrypting the encrypted text with private key
	decryptedText, err2 := ecies.Decrypt(xPrivateKey, encryptedText)
	if err2 != nil {
		log.Fatal("Error decrypting text: ", err2)
	}
	if !bytes.Equal([]byte(secert), []byte(decryptedText)) {
		log.Fatal("Ops... decrypted data doesn't match original ", encryptedText, "  ", decryptedText)
	} else {
		log.Println("Key have been matched!")
	}

	//checking if key generated are capable for signing purpose using ecdsa formats
	catchHash, pubKeyInHex := cvs.Sign(xPrivateKey.Hex(), xPrivateKey.PublicKey.Hex(true), secert)
	log.Println("String Hash of Data:", catchHash)

	//verifying the hashed data via the private key
	check := cvs.Verify(catchHash, pubKeyInHex, secert)
	if check {
		log.Println("signing has been verified")
	} else {
		log.Println("signing has not been verified")
	}
}
