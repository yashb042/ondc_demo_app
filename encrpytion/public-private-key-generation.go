package main

import "fmt"

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	b64 "encoding/base64"
	"maze.io/x/crypto/x25519"
)

type pkcs8 struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
	// optional attributes omitted.
}

type pkixPublicKey struct {
	Algo      pkix.AlgorithmIdentifier
	BitString asn1.BitString
}

func base64Encode(payload []byte) string {
	return b64.StdEncoding.EncodeToString(payload)
}

func generateEncryptionKeys() (string, string, error) {
	//publicKey, privateKey, err := ed25519.GenerateKey(nil)
	privateKey, err := x25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Println("Error generating x25519 keys for encryption")
		return "", "", err
	}

	marshaledPrivateKey, err := marshalX25519PrivateKey(privateKey.Bytes())
	if err != nil {
		fmt.Println("Error marshaling enc private key to x509.pkcs format", err)
		return "", "", err
	}

	marshaledPublicKey, err := marshalX25519PublicKey(privateKey.PublicKey.Bytes())
	if err != nil {
		fmt.Println("Error marshaling enc public key to x509 format", err)
		return "", "", err
	}

	return base64Encode(marshaledPublicKey), base64Encode(marshaledPrivateKey), nil
}

func marshalX25519PrivateKey(key []byte) ([]byte, error) {
	var privateKey []byte
	curveKey, err := asn1.Marshal(key[:32])
	if err != nil {
		fmt.Println("Error asn1 marshaling private key")
		return privateKey, err
	}
	pkcsKey := pkcs8{
		Version: 1,
		Algo: pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 3, 101, 110},
		},
		PrivateKey: curveKey,
	}
	privateKey, err = asn1.Marshal(pkcsKey)
	if err != nil {
		fmt.Println("Error asn1 marshaling pkcs8 key", err)
		return privateKey, err
	}
	return privateKey, nil
}

func marshalX25519PublicKey(key []byte) ([]byte, error) {
	x509Key := pkixPublicKey{
		Algo: pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 3, 101, 110},
		},
		BitString: asn1.BitString{
			Bytes:     key,
			BitLength: 8 * len(key),
		},
	}
	publicKey, err := asn1.Marshal(x509Key)
	if err != nil {
		fmt.Println("Error asn1 marshaling public key", err)
		return publicKey, err
	}
	return publicKey, nil
}

func generateSigningKeys() (string, string, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		fmt.Println("Error generating signing keys", err)
		return "", "", err
	}

	return base64Encode(publicKey), base64Encode(privateKey), nil
}

func main() {
	signingPublicKey, signingPrivateKey, err := generateSigningKeys()
	if err != nil {
		fmt.Println("Could not generate signing keys")
		return
	}
	encPublicKey, encPrivateKey, err := generateEncryptionKeys()
	if err != nil {
		fmt.Println("Could not generate encryption keys")
		return
	}
	fmt.Println("Signing_private_key:", signingPrivateKey)
	fmt.Println("Signing_public_key:", signingPublicKey)
	fmt.Println("Crypto_Privatekey:", encPrivateKey)
	fmt.Println("Crypto_Publickey:", encPublicKey)
}
