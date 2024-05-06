package cryptoUtils

import (
	"bytes"
	"crypto/aes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	b64 "encoding/base64"
	"errors"
	"fmt"
	"ondc-buyer/demo_app/configs"
	"os"
	"regexp"
	"time"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/curve25519"
	"maze.io/x/crypto/x25519"
)

type pkcs8 struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
	// optional attributes omitted.
}

type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

type pkixPublicKey struct {
	Algo      pkix.AlgorithmIdentifier
	BitString asn1.BitString
}

func base64Decode(payload string) ([]byte, error) {
	return b64.StdEncoding.DecodeString(payload)
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

func parseX25519PrivateKey(key string) ([]byte, error) {
	var parsedKey []byte
	decoded, err := base64Decode(key)
	if err != nil {
		fmt.Println("Error base64 decoding x25519 private key", err)
		return parsedKey, err
	}

	var pkcsKey pkcs8
	_, err = asn1.Unmarshal(decoded, &pkcsKey)
	if err != nil {
		fmt.Println("Error asn1 unmarshaling x25519 private key", err)
		return parsedKey, err
	}

	_, err = asn1.Unmarshal(pkcsKey.PrivateKey, &parsedKey)
	if err != nil {
		fmt.Println("Error asn1 unmashaling pkcs privat key", err)
		return parsedKey, err
	}
	return parsedKey, nil
}

func parseX25519PublicKey(key string) ([]byte, error) {
	var parsedKey []byte

	decoded, err := base64Decode(key)
	if err != nil {
		fmt.Println("Error base64 decoding x25519 public key", err)
		return parsedKey, err
	}

	var x509Key publicKeyInfo
	_, err = asn1.Unmarshal(decoded, &x509Key)
	if err != nil {
		fmt.Println("Error asn1 unmarshaling x25519 public key", err)
		return parsedKey, err
	}

	return x509Key.PublicKey.RightAlign(), nil
}

func aesEncrypt(payload []byte, key []byte) ([]byte, error) {
	cipher, err := aes.NewCipher(key)
	blockSize := cipher.BlockSize()
	if err != nil {
		fmt.Println("Error creating AES cipher", err)
		return nil, err
	}
	size := len(payload)
	if size%blockSize != 0 {
		remainder := blockSize - (size % blockSize)
		pad := bytes.Repeat([]byte(" "), remainder)
		payload = append(payload, pad...)
		size = len(payload)
	}

	buf := make([]byte, blockSize)
	var encrypted []byte
	for i := 0; i < size; i += blockSize {
		cipher.Encrypt(buf, payload[i:i+blockSize])
		encrypted = append(encrypted, buf...)
	}
	return encrypted, nil
}

func Unpad(data []byte, blockSize uint) ([]byte, error) {
	if blockSize < 1 {
		return nil, fmt.Errorf("Block size looks wrong")
	}

	if uint(len(data))%blockSize != 0 {
		return nil, fmt.Errorf("Data isn't aligned to blockSize")
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("Data is empty")
	}

	paddingLength := int(data[len(data)-1])
	for _, el := range data[len(data)-paddingLength:] {
		if el != byte(paddingLength) {
			return nil, fmt.Errorf("Padding had malformed entries. Have '%x', expected '%x'", paddingLength, el)
		}
	}

	return data[:len(data)-paddingLength], nil
}

func aesDecrypt(cipherText []byte, key []byte) ([]byte, error) {
	cipher, err := aes.NewCipher(key)
	blockSize := cipher.BlockSize()
	if err != nil {
		fmt.Println("Error creating AES cipher", err)
		return nil, err
	}
	size := len(cipherText)
	buf := make([]byte, blockSize)
	var plainText []byte
	for i := 0; i < size; i += blockSize {
		cipher.Decrypt(buf, cipherText[i:i+blockSize])
		plainText = append(plainText, buf...)
	}
	plainText, err = Unpad(plainText, uint(blockSize))
	return plainText, nil
}

func generateSigningKeys() (string, string, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		fmt.Println("Error generating signing keys", err)
		return "", "", err
	}

	return base64Encode(publicKey), base64Encode(privateKey), nil
}

func signRequest(privateKey string, payload []byte, currentTime int, ttl int) (string, error) {
	//compute blake 512 hash over the payload
	hash := blake2b.Sum512(payload)
	digest := base64Encode(hash[:])

	//create a signature and then sign with ed25519 private key
	signatureBody := fmt.Sprintf("(created): %d\n(expires): %d\ndigest: BLAKE-512=%s", currentTime, currentTime+ttl, digest)
	decodedKey, err := base64Decode(privateKey)
	if err != nil {
		fmt.Println("Error decoding signing private key", err)
		return "", err
	}
	signature := ed25519.Sign(decodedKey, []byte(signatureBody))
	return base64Encode(signature), nil
}

func SignRequestForVlookup(privateKey string, ondcDomain string, city string, subscriberId string) (string, error) {
	signatureBody := fmt.Sprintf("IND|%s|sellerApp|%s|%s", ondcDomain, city, subscriberId)
	decodedKey, err := base64Decode(privateKey)
	if err != nil {
		fmt.Println("Error decoding signing private key", err)
		return "", err
	}
	signature := ed25519.Sign(decodedKey, []byte(signatureBody))
	return base64Encode(signature), nil
}

func GenerateAuthorizationHeader(payload interface{}) (string, error) {
	var authHeader string

	privateKey := configs.GlobalConfigs.OndcConfigs.SigningPrivateKey
	currentTime := int(time.Now().Unix())

	//ttl we are using is 30 seconds
	ttl := 30
	signature, err := signRequest(privateKey, convertInterfaceToBytes(payload), currentTime, ttl)
	if err != nil {
		fmt.Println("Could not compute signature", err)
		return authHeader, err
	}

	subscriberID := configs.GlobalConfigs.OndcConfigs.SubscriberId
	uniqueKeyID := configs.GlobalConfigs.OndcConfigs.SubscribeUniqueId

	authHeader = fmt.Sprintf(`Signature keyId="%s|%s|ed25519",algorithm="ed25519",created="%d",expires="%d",headers="(created) (expires) digest",signature="%s"`, subscriberID, uniqueKeyID, currentTime, currentTime+ttl, signature)

	return authHeader, nil
}

func VerifyRequest(payload interface{}, authHeader string, sellerPublicKey string) bool {
	_, created, expires, signature, err := parseAuthHeader(authHeader)
	if err != nil {
		return false
	}

	//compute blake 512 hash over the payload
	interfaceToBytes := convertInterfaceToBytes(payload)
	print("Payload to be hashed", interfaceToBytes)
	hash := blake2b.Sum512(interfaceToBytes)
	digest := base64Encode(hash[:])

	//create a signature and then sign with ed25519 private key
	computedMessage := fmt.Sprintf("(created): %s\n(expires): %s\ndigest: BLAKE-512=%s", created, expires, digest)
	publicKeyBytes, err := base64Decode(sellerPublicKey)
	if err != nil {
		print("Error decoding public key", err)
		return false
	}
	receivedSignature, err := base64Decode(signature)
	if err != nil {
		print("Unable to base64 decode received signature", err)
		return false
	}
	return ed25519.Verify(publicKeyBytes, []byte(computedMessage), receivedSignature)
}

func parseAuthHeader(authHeader string) (string, string, string, string, error) {
	signatureRegex := regexp.MustCompile(`keyId=\"(.+?)\".+?created=\"(.+?)\".+?expires=\"(.+?)\".+?signature=\"(.+?)\"`)
	groups := signatureRegex.FindAllStringSubmatch(authHeader, -1)
	if len(groups) > 0 && len(groups[0]) > 4 {
		return groups[0][1], groups[0][2], groups[0][3], groups[0][4], nil
	}
	print("Error parsing auth header. Please make sure that the auh headers passed as command line argument is valid")
	return "", "", "", "", errors.New("error parsing auth header")
}

func convertInterfaceToBytes(payload interface{}) []byte {
	var byteSlice []byte
	if uint8Slice, ok := payload.([]uint8); ok {
		//log.LibraryLogger.Info("Payload is already a byte slice")
		byteSlice = make([]byte, len(uint8Slice))
		for i, v := range uint8Slice {
			byteSlice[i] = v
		}
	}
	return byteSlice
}

func encrypt(privateKey string, publicKey string) (string, error) {
	var encryptedText string
	parsedPrivateKey, err := parseX25519PrivateKey(privateKey)
	if err != nil {
		fmt.Println("Error parsing private key.", err)
		return encryptedText, err
	}

	parsedPublicKey, err := parseX25519PublicKey(publicKey)
	if err != nil {
		fmt.Println("Error parsing public key.", err)
		return encryptedText, err
	}

	secretKey, err := curve25519.X25519(parsedPrivateKey, parsedPublicKey)
	if err != nil {
		fmt.Println("Error constructing secret key", err)
		return encryptedText, nil
	}

	plainText := "ONDC is a Great Initiative!"
	cipherBytes, err := aesEncrypt([]byte(plainText), secretKey)
	if err != nil {
		fmt.Println("Error encrypting with AES", err)
		return encryptedText, err
	}

	encryptedText = base64Encode(cipherBytes)
	return encryptedText, nil
}

func Decrypt(privateKey string, publicKey string, cipherText string) (string, error) {
	print("Decrypting the cipher text")
	print("Crypto Private Key: ", privateKey)
	print("Crypto Public Key: ", publicKey)
	print("Cipher Text: ", cipherText)

	var decryptedText string
	parsedPrivateKey, err := parseX25519PrivateKey(privateKey)
	if err != nil {
		fmt.Println("Error parsing private key.", err)
		return decryptedText, err
	}

	parsedPublicKey, err := parseX25519PublicKey(publicKey)
	if err != nil {
		fmt.Println("Error parsing public key.", err)
		return decryptedText, err
	}

	secretKey, err := curve25519.X25519(parsedPrivateKey, parsedPublicKey)
	if err != nil {
		fmt.Println("Error constructing secret key", err)
		return decryptedText, nil
	}

	cipherBytes, err := base64Decode(cipherText)
	if err != nil {
		fmt.Println("Error base64 decoding cipher text", err)
		return decryptedText, err
	}
	plainBytes, err := aesDecrypt(cipherBytes, secretKey)
	if err != nil {
		fmt.Println("Error decrypting with AES", err)
		return decryptedText, err
	}

	decryptedText = string(plainBytes)
	return decryptedText, nil
}

func CreateSignedData(data, privateKey string) (string, error) {
	privateKeyBytes, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		return "", fmt.Errorf("error decoding private key: %w", err)
	}

	// Ensure the private key is the correct length
	if len(privateKeyBytes) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("invalid private key length")
	}

	// Generate the detached signature
	signature := ed25519.Sign(privateKeyBytes, []byte(data))

	// Convert the signature to base64
	signatureBase64 := base64.StdEncoding.EncodeToString(signature)

	print("Signed Message: ", signatureBase64)
	return signatureBase64, nil
}

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		fmt.Println("Missing paramsters. Try ./crypto generate_key_pairs")
		return
	}

	switch args[0] {
	case "generate_key_pairs":
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
	case "create_authorisation_header":
		payload := []byte(args[1])
		authHeader, err := GenerateAuthorizationHeader(payload)
		if err == nil {
			fmt.Println(authHeader)
		}
	case "verify_authorisation_header":
		authHeader := args[1]
		fmt.Println(VerifyRequest([]byte{}, authHeader, ""))
	case "encrypt":
		privateKey := args[1]
		publicKey := args[2]
		cipherText, err := encrypt(privateKey, publicKey)
		if err == nil {
			fmt.Println(cipherText)
		}
	case "decrypt":
		privateKey := "MC4CAQEwBQYDK2VuBCIEIFCyap+I0JgZ8L0tyFCVzDpuav/pP4VKA7QmzCuAqVRM"
		publicKey := "MCowBQYDK2VuAyEAduMuZgmtpjdCuxv+Nc49K0cB6tL/Dj3HZetvVN7ZekM="
		cipherText := "JwvEAGgEGCpdvWa1c9mzu5DVT4Pqd3ZxRPwbOvuYCT4mCX8Fmbx6KbCWJqOIHwPw"
		plainText, err := Decrypt(privateKey, publicKey, cipherText)
		if err == nil {
			fmt.Println(plainText)
		}

	case "sign_header":
		//fmt.Println(signRequestForVlookup(args[1]))

	}
}
