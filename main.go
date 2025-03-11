package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Lalka121/filecrypt/textstyler"
)

type KeyInfo struct {
	Key         string `json:"key"`
	Description string `json:"description,omitempty"`
}

type KeyStore struct {
	Keys map[string]KeyInfo `json:"keys"`
}

var (
	keysDir  string
	keyStore KeyStore
)

func init() {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Printf("Ошибка получения домашней директории: %v\n", err)
		os.Exit(1)
	}
	keysDir = filepath.Join(homeDir, ".file_encrypter")
	if err := os.MkdirAll(keysDir, 0700); err != nil {
		fmt.Printf("Ошибка создания директории для ключей: %v\n", err)
		os.Exit(1)
	}
	loadKeys()
}

func loadKeys() {
	keyStore.Keys = make(map[string]KeyInfo)
	keysPath := filepath.Join(keysDir, "keys.json")

	data, err := os.ReadFile(keysPath)
	if err != nil {
		if !os.IsNotExist(err) {
			fmt.Printf("%s %v\n", textstyler.Error("Ошибка чтения файла ключей:"), err)
		}
		return
	}

	if err := json.Unmarshal(data, &keyStore); err != nil {
		fmt.Printf("%s %v\n", textstyler.Error("Ошибка декодирования файла ключей:"), err)
	}
}

func saveKeys() {
	keysPath := filepath.Join(keysDir, "keys.json")
	data, err := json.MarshalIndent(keyStore, "", "  ")
	if err != nil {
		fmt.Printf("%s %v\n", textstyler.Error("Ошибка кодирования ключей:"), err)
		return
	}

	if err := os.WriteFile(keysPath, data, 0600); err != nil {
		fmt.Printf("%s %v\n", textstyler.Error("Ошибка кодирования ключей:"), err)
	}
}

func generateKey(id string, description string) {
	if _, exists := keyStore.Keys[id]; exists {
		fmt.Printf("%s %s\n", textstyler.Error("Ошибка кодирования ключей:"), fmt.Sprintf("Ключ с ID '%s' уже существует\n", id))
		return
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		fmt.Printf("%s %v\n", textstyler.Error("Ошибка кодирования ключей:"), err)
		return
	}

	encodedKey := base64.StdEncoding.EncodeToString(key)
	keyStore.Keys[id] = KeyInfo{
		Key:         encodedKey,
		Description: description,
	}
	saveKeys()
	fmt.Printf("%s ID: %s\n", textstyler.Success("Успешно создан новый ключ."), id)
}

func getKey(id string) ([]byte, error) {
	keyInfo, exists := keyStore.Keys[id]
	if !exists {
		return nil, fmt.Errorf("ключ с ID '%s' не найден", id)
	}

	key, err := base64.StdEncoding.DecodeString(keyInfo.Key)
	if err != nil {
		return nil, fmt.Errorf("неверный формат ключа: %v", err)
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
		return errors.New("неверный формат зашифрованных данных")
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

func listKeys() {
	if len(keyStore.Keys) == 0 {
		fmt.Println("Нет сохраненных ключей")
		return
	}

	fmt.Println(textstyler.Title("Список ключей:"))
	fmt.Println(textstyler.Subtitlef("Всего: %d", len(keyStore.Keys)))
	for id, keyInfo := range keyStore.Keys {
		fmt.Printf("- %s %s\n", textstyler.Label("ID:"), id)
		desc := keyInfo.Description
		if desc != "" {
			fmt.Printf("  %s %s\n", textstyler.Label("Описание:"), desc)
		}
	}
}

func main() {
	if len(os.Args) < 2 {
		printHelp()
		return
	}

	command := os.Args[1]
	switch command {
	case "generate-key":
		fs := flag.NewFlagSet("generate-key", flag.ExitOnError)
		desc := fs.String("m", "", "Описание ключа")
		fs.Parse(os.Args[2:])

		if fs.NArg() != 1 {
			fmt.Println("Использование: generate-key [-m описание] <идентификатор-ключа>")
			return
		}
		generateKey(fs.Arg(0), *desc)

	case "encrypt":
		if len(os.Args) != 4 {
			fmt.Println("Использование: encrypt <файл> <идентификатор-ключа>")
			return
		}
		if err := encryptFile(os.Args[2], os.Args[3]); err != nil {
			fmt.Printf("%s %v\n", textstyler.Error("Ошибка шифрования:"), err)
		} else {
			fmt.Println(textstyler.Success("Файл успешно зашифрован"))
		}

	case "decrypt":
		if len(os.Args) != 4 {
			fmt.Println("Использование: decrypt <файл> <идентификатор-ключа>")
			return
		}
		if err := decryptFile(os.Args[2], os.Args[3]); err != nil {
			fmt.Printf("%s %v\n", textstyler.Error("Ошибка дешифрования:"), err)
		} else {
			fmt.Println(textstyler.Success("Файл успешно расшифрован"))
		}

	case "list-key":
		listKeys()

	case "help":
		printHelp()

	default:
		fmt.Println(textstyler.Errorf("Команда не распознана\n"))
		printHelp()
	}
}

func printHelp() {
	fmt.Println(textstyler.Title("Шифровщик/Дешифровщик файлов"))
	fmt.Println(textstyler.Subtitle("Использование:"))
	fmt.Println("  generate-key [-m описание] <идентификатор>  Создать новый ключ")
	fmt.Println("  encrypt <файл> <идентификатор>             Зашифровать файл")
	fmt.Println("  decrypt <файл> <идентификатор>             Дешифровать файл")
	fmt.Println("  list-key                                   Показать все ключи")
}