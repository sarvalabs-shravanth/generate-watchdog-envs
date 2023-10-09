package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

func GenerateRandomBytes(length int) ([]byte, error) {
	key := make([]byte, length)

	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func GenerateAPIKey() (string, error) {
	key, err := GenerateRandomBytes(32)
	if err != nil {
		return "", err
	}

	encodedKey := base64.URLEncoding.EncodeToString(key)

	return encodedKey, nil
}

func generateAESKey() ([]byte, error) {
	key := make([]byte, 32) // 32 bytes for AES-256
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func generateIV() ([]byte, error) {
	iv := make([]byte, 12) // 12 bytes for AES GCM
	_, err := rand.Read(iv)
	if err != nil {
		return nil, err
	}
	return iv, nil
}

// Hex2Bytes decodes string to []byte
func Hex2Bytes(str string) ([]byte, error) {
	h, err := hex.DecodeString(str)
	if err != nil {
		return nil, err
	}

	return h, nil
}

func EncryptAPIKey(apiKey, keyHex, ivHex string) (string, error) {
	plaintext := []byte(apiKey)

	key, err := Hex2Bytes(keyHex)
	if err != nil {
		return "", err
	}

	iv, err := Hex2Bytes(ivHex)
	if err != nil {
		return "", err
	}

	// Create a new AES cipher block using the provided key
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Create a new AES GCM mode cipher using the block and IV
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Encrypt the plaintext API key using AES GCM mode
	ciphertext := aesgcm.Seal(nil, iv, plaintext, nil)

	// Concatenate IV and ciphertext and encode them to base64 string
	encoded := base64.URLEncoding.EncodeToString(append(iv, ciphertext...))

	return encoded, nil
}

func HashAPIKey(apiKey string) (string, error) {
	// Create a new SHA256 hash
	hash := sha256.New()

	// Write the API key to the hash
	_, err := hash.Write([]byte(apiKey))
	if err != nil {
		return "", err
	}

	// Get the hash sum
	hashSum := hash.Sum(nil)

	// Convert the hash sum to a hexadecimal string
	hashString := hex.EncodeToString(hashSum)

	return hashString, nil
}

func main() {

	apiKey, err := GenerateAPIKey()
	if err != nil {
		return
	}

	fmt.Println("X-API-Key: ", apiKey)

	key, err := generateAESKey()
	if err != nil {
		fmt.Println("Error generating AES key:", err)
		return
	}

	// Convert the key to a hexadecimal string and print it
	keyHex := hex.EncodeToString(key)
	fmt.Println("export ENCRYPTION_KEY=", keyHex)

	iv, err := generateIV()
	if err != nil {
		fmt.Println("Error generating IV:", err)
		return
	}

	// Convert the IV to a hexadecimal string and print it
	ivHex := hex.EncodeToString(iv)
	fmt.Println("export ENCRYPTION_NONCE=", ivHex)

	encryptedAPIKey, err := EncryptAPIKey(apiKey, keyHex, ivHex)
	if err != nil {
		fmt.Println("err:", err)
		return
	}

	hashedAPIKey, err := HashAPIKey(encryptedAPIKey)
	if err != nil {
		fmt.Println("err:", err, "error: Failed to hash access key")
		return
	}

	fmt.Println("export WATCHDOG_HASHED_API=", hashedAPIKey)
}
