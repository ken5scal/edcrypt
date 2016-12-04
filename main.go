package main

import (
	"crypto/aes"
	"fmt"
	"crypto/cipher"
	"crypto/rand"
)

func main() {
	plainText := "1234123412341234"

	key := []byte("1234123412341234123412341234123") // Not AES-128, 256, 512(bit)
	fmt.Println(EncryptByBlockSecretKey(key, plainText))

	key = []byte("1234123412341234") // AES-128
	fmt.Println(EncryptByBlockSecretKey(key, "12341234123412345")) // Longer than 16 byte

	key = []byte("1234123412341234") // AES-128
    fmt.Println(EncryptByBlockSecretKey(key, "123412341234123")) // Shorter than 16 byte

	cipherText,_ := EncryptByBlockSecretKey(key, plainText)
	fmt.Println(cipherText)

	plainText = DecryptByBlockSecretKey(key, cipherText)
	fmt.Println(plainText)

	cipherText, _ = EncryptByCBCMode(key, "1234567891234567") // 16bye
	fmt.Println(cipherText)
	cipherText, _ = EncryptByCBCMode(key, "12345678912345671234123412341234") // 32byte
	fmt.Println(cipherText)

	plainText, _ = DecryptByCBCMode(key, cipherText)
	fmt.Println(plainText)
}

// Only AES at this moment
func EncryptByBlockSecretKey(key []byte, plainText string) ([]byte, error) {
	c, err := aes.NewCipher(key); if err != nil {
		return nil, err
	}
	cipherText := make([]byte, aes.BlockSize)

	c.Encrypt(cipherText, []byte(plainText)) // Input/Output must be 16bits large
	return cipherText, nil
}

func EncryptByCBCMode(key []byte, plainText string) ([]byte, error) {
	if len(plainText) % aes.BlockSize != 0 {
		panic("Plain text must be multiple of 128bit")
	}

	block, err := aes.NewCipher(key); if err != nil {
		return nil, err
	}

	// TODO: Im not still understanding why many example says "Secure cipherText size to include IV"
	// I think I understand. return cipher text to include iv for decrypting it later
	cipherText := make([]byte,  aes.BlockSize + len(plainText)) // cipher text must be larger than plaintext
	iv := cipherText[:aes.BlockSize] // Unique iv is required
	_, err = rand.Read(iv); if err != nil {
		return nil, err
	}

	cbc := cipher.NewCBCEncrypter(block, iv)
	cbc.CryptBlocks(cipherText[aes.BlockSize:], []byte(plainText))

	return cipherText, nil
}

// Only AES at this moment
func DecryptByBlockSecretKey(key []byte, cipherText []byte) string {
	c, err := aes.NewCipher(key); if err != nil {
		fmt.Println(err.Error())
		return ""
	}

	plainText := make([]byte, aes.BlockSize)
	c.Decrypt(plainText, cipherText)

	return string(plainText)
}

func DecryptByCBCMode(key []byte, cipherText []byte) (string ,error) {
	block , err := aes.NewCipher(key); if err != nil {
		return "", err
	}

	if len(cipherText) < aes.BlockSize {
		panic("cipher text must be longer than blocksize")
	} else if len(cipherText) % aes.BlockSize != 0 {
		panic("cipher text must be multiple of blocksize(128bit)")
	}
	iv := cipherText[:aes.BlockSize] // assuming iv is stored in the first block of ciphertext
	cipherText = cipherText[aes.BlockSize:]
	plainText := make([]byte, len(cipherText))

	cbc := cipher.NewCBCDecrypter(block, iv)
	cbc.CryptBlocks(plainText, cipherText)
	fmt.Println(plainText)
	return string(plainText), nil
}
