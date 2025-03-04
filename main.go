package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type KeyStore struct {
	Keys map[string]string `json:"keys"`
}

var (
	keysDir  string
	keyStore KeyStore
)

func init() {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Printf("Error getting home directory: %v\n", err)
		os.Exit(1)
	}
	keysDir = filepath.Join(homeDir, ".file_encrypter")
	if err := os.MkdirAll(keysDir, 0700); err != nil {
		fmt.Printf("Error creating keys directory: %v\n", err)
		os.Exit(1)
	}
	loadKeys()
}

func loadKeys() {
	keyStore.Keys = make(map[string]string)
	keysPath := filepath.Join(keysDir, "keys.json")

	data, err := os.ReadFile(keysPath)
	if err != nil {
		if !os.IsNotExist(err) {
			fmt.Printf("Error reading keys file: %v\n", err)
		}
		return
	}

	if err := json.Unmarshal(data, &keyStore); err != nil {
		fmt.Printf("Error decoding keys file: %v\n", err)
	}
}

func saveKeys() {
	keysPath := filepath.Join(keysDir, "keys.json")
	data, err := json.MarshalIndent(keyStore, "", "  ")
	if err != nil {
		fmt.Printf("Error encoding keys: %v\n", err)
		return
	}

	if err := os.WriteFile(keysPath, data, 0600); err != nil {
		fmt.Printf("Error saving keys file: %v\n", err)
	}
}

func generateKey(id string) {
	if _, exists := keyStore.Keys[id]; exists {
		fmt.Printf("Key with ID '%s' already exists\n", id)
		return
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		fmt.Printf("Error generating key: %v\n", err)
		return
	}

	encodedKey := base64.StdEncoding.EncodeToString(key)
	keyStore.Keys[id] = encodedKey
	saveKeys()
	fmt.Printf("Successfully generated new key with ID: %s\n", id)
}

func getKey(id string) ([]byte, error) {
	encodedKey, exists := keyStore.Keys[id]
	if !exists {
		return nil, fmt.Errorf("key with ID '%s' not found", id)
	}

	key, err := base64.StdEncoding.DecodeString(encodedKey)
	if err != nil {
		return nil, fmt.Errorf("invalid key format: %v", err)
	}

	return key, nil
}

func encryptFile(srcPath, id string) error {
	key, err := getKey(id)
	if err != nil {
		return err
	}

	hashedKey := sha256.Sum256(key)
	block, err := aes.NewCipher(hashedKey[:])
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	srcFile, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	plaintext, err := io.ReadAll(srcFile)
	if err != nil {
		return err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	dstPath := srcPath + ".enc"
	if err := os.WriteFile(dstPath, ciphertext, 0644); err != nil {
		return err
	}

	return nil
}

func decryptFile(srcPath, id string) error {
	key, err := getKey(id)
	if err != nil {
		return err
	}

	hashedKey := sha256.Sum256(key)
	block, err := aes.NewCipher(hashedKey[:])
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	ciphertext, err := os.ReadFile(srcPath)
	if err != nil {
		return err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return errors.New("invalid ciphertext")
	}

	nonce, ciphertext := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return err
	}

	dstPath := srcPath[:len(srcPath)-4]
	if err := os.WriteFile(dstPath, plaintext, 0644); err != nil {
		return err
	}

	return nil
}

func main() {
	if len(os.Args) < 2 {
		printHelp()
		return
	}

	command := os.Args[1]
	switch command {
	case "generate-key":
		if len(os.Args) != 3 {
			fmt.Println("Usage: generate-key <key-id>")
			return
		}
		generateKey(os.Args[2])

	case "encrypt":
		if len(os.Args) != 4 {
			fmt.Println("Usage: encrypt <file> <key-id>")
			return
		}
		if err := encryptFile(os.Args[2], os.Args[3]); err != nil {
			fmt.Printf("Encryption failed: %v\n", err)
		} else {
			fmt.Println("File encrypted successfully")
		}

	case "decrypt":
		if len(os.Args) != 4 {
			fmt.Println("Usage: decrypt <file> <key-id>")
			return
		}
		if err := decryptFile(os.Args[2], os.Args[3]); err != nil {
			fmt.Printf("Decryption failed: %v\n", err)
		} else {
			fmt.Println("File decrypted successfully")
		}

	default:
		printHelp()
	}
}

func printHelp() {
	fmt.Println("File Encrypter/Decrypter")
	fmt.Println("Usage:")
	fmt.Println("  generate-key <key-id>    Generate new encryption key")
	fmt.Println("  encrypt <file> <key-id>  Encrypt file")
	fmt.Println("  decrypt <file> <key-id>  Decrypt file")
}