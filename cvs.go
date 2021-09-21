package cvs

import (
	"crypto/ecdsa"
	"encoding/hex"
	"log"
	"reflect"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

//EncryptECWithPublicKey using EC (with secp256k1 parameters) public key in hexadecimal string format encrypt a string
func EncryptECWithPublicKey(pubKeyInHexaString, textToEncrypt string) (encryptedText string, err error) {
	err = nil
	pubKeyInHexaString = strings.TrimPrefix(pubKeyInHexaString, "0x")
	dst := make([]byte, hex.DecodedLen(len(pubKeyInHexaString)))
	chavePublicaEmInt, err := hex.Decode(dst, []byte(pubKeyInHexaString))
	if err != nil {
		log.Fatal("[EncryptECDSAWithPublicKey] Error decoding pubKey to Int: ", err.Error())
		return
	}
	dst = dst[:chavePublicaEmInt]

	//log.Printf("[EncryptECDSAWithPublicKey]  PubKey: %s\n", dst)
	chavePublicaECDSA, err := secp256k1.ParsePubKey(dst)
	if err != nil {
		log.Fatal("Error parsing PubKey:", err)
		return
	}

	out, err := secp256k1.Encrypt(chavePublicaECDSA, []byte(textToEncrypt))
	if err != nil {
		log.Fatal("[EncryptECDSAWithPublicKey] failed to encrypt: ", err)
		return
	}
	encryptedText = string(out)
	return
}

//DecryptWithECPrivateKey decrypt a text using EC (with secp256k1 parameters) private key
func DecryptWithECPrivateKey(privateKey, encryptedText string) (decryptedText string, err error) {
	chavePrivadaEmHexadecimal := hex.EncodeToString([]byte(privateKey))
	chavePrivadaEmECDSA, err := crypto.HexToECDSA(chavePrivadaEmHexadecimal)
	chavePrivadaDecred := secp256k1.NewPrivateKey(chavePrivadaEmECDSA.D)
	if err != nil {
		log.Fatal("[DecryptWithECPrivateKey] Error generating private key from text: ", err)
		return
	}

	dec, err := secp256k1.Decrypt(chavePrivadaDecred, []byte(encryptedText))
	if err != nil {
		log.Fatal("[DecryptWithECPrivateKey] failed to decrypt:", err)
	}
	decryptedText = string(dec)
	return
}

//signing a text message
func Sign(PrivateKey string, PublicKey string, secertKey string) (hashOfData string, publicKeyInHex string) {
	chavePrivada := PrivateKey // private key
	//chavePrivadaEmHexadecimal := hex.EncodeToString([]byte(chavePrivada))    // private key in hexadecimal
	chavePrivadaEmECDSA, err := crypto.HexToECDSA(chavePrivada) // private key in ECDSA
	if err != nil {
		log.Fatal("Error generating private key in ECDSA ", err)
	}

	chavePublica := chavePrivadaEmECDSA.Public()               //public key in ECDSA
	chavePublicaEmECDSA, ok := chavePublica.(*ecdsa.PublicKey) //checking if chavePublica is in Publickey format
	if !ok {
		log.Fatal("It was not possible to cast the public key to ECDSA")
	}

	log.Println("we have the keys...")
	log.Println("")
	log.Println("private key ", chavePrivada)
	log.Println("")
	log.Println("private key in Hexadecimal ", chavePrivada) //em
	log.Println("")
	log.Printf("private key in ECDSA %+v\n\n", chavePrivadaEmECDSA)
	log.Printf("public key object %+v\n\n", chavePublica)
	log.Printf("public key object in ECDSA %+v\n\n\n", chavePublicaEmECDSA)

	chavePublicaEmBytes := crypto.FromECDSAPub(chavePublicaEmECDSA) // publickey in bytes -> publickey object
	chavePublicaEmHexaString := hexutil.Encode(chavePublicaEmBytes) //encoding publickey object into hexa
	log.Println("public key object in Hexadecimal ", chavePublicaEmHexaString)

	dado := secertKey
	hash := crypto.Keccak256Hash([]byte(dado))                     // hash of dado
	log.Printf("Hash of data to be signed %+v\n\n", hash.String()) // hash to string
	log.Printf("hash type \n", (reflect.TypeOf(hash.String())))
	assinatura, err := crypto.Sign(hash.Bytes(), chavePrivadaEmECDSA) //sign privatekey in ECDSA format with hash
	if err != nil {
		log.Fatal("Error signing data ", err)
	}

	log.Printf("\nO dice signed in hex: %s\nA public key in Hexa: %s\n", hexutil.Encode(assinatura), chavePublicaEmHexaString)
	//var str_hash string = hash.String()

	return hexutil.Encode(assinatura), chavePublicaEmHexaString
}

//verifying any signed text message
func Verify(hashOfSignedData string, publicKeyInHex string, secertKey string) (veri bool) {
	//dadoAssinadoEmHexa = data signed in hexa = "0xa3d46b97492d362769420dbe0bcc87910579fb92e66c106d8c7fe029d00845882fc02d9149a63c9f9feee8e6e16f11edb5f7ae0cfb4e437ef1f5230c0336070c01"
	//assinatura = signature
	//chavePublicaEmHexa = Public Key in hexa
	//chavePublica = Public key = "0x04f7270a93ba0c2ec6686797da050bd602293a3d6cc53d6b86758d44cae22813e9e864682e9e9d351bbfb65cadedf62d2687c78bf2fd9146be23172026f001ecdd"
	dadoAssinadoEmHexa := hashOfSignedData
	assinatura, err := hexutil.Decode(dadoAssinadoEmHexa)
	if err != nil {
		log.Fatalf("Failed to decode assumption for byte array %+v\n", err)
	}
	assinaturaSemRecoverID := assinatura[:len(assinatura)-1]

	chavePublicaEmHexa := publicKeyInHex
	chavePublica, err := hexutil.Decode(chavePublicaEmHexa)
	if err != nil {
		log.Fatalf("Failed to decode public key for byte array %+v\n", err)
	}

	dado := secertKey
	hash := crypto.Keccak256Hash([]byte(dado))

	verificado := crypto.VerifySignature(chavePublica, hash.Bytes(), assinaturaSemRecoverID)
	log.Println("Is the signature verified? ", verificado)
	return verificado
}
