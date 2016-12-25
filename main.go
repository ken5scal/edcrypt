package main

import (
	"crypto/aes"
	"fmt"
	"crypto/cipher"
	"crypto/rand"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
)

func main() {
	plainText := "1234123412341234"

	key := []byte("1234123412341234123412341234123") // Not AES-128, 256, 512(bit)
	fmt.Println(EncryptByBlockSecretKey(key, plainText))

	key = []byte("1234123412341234") // AES-128
	fmt.Println(EncryptByBlockSecretKey(key, "12341234123412345")) // Longer than 16 byte

	 //This will result in Panic
	//fmt.Println(EncryptByBlockSecretKey(key, "123412341234123")) // Shorter than 16 byte

	cipherText, _ := EncryptByBlockSecretKey(key, plainText)
	fmt.Println(cipherText)

	plainText = DecryptByBlockSecretKey(key, cipherText)
	fmt.Println(plainText)

	plainText = "1234567891234567"
	cipherText, _ = EncryptByCBCMode(key, plainText) // 16bye
	fmt.Printf("Plaintext %v is encrypted into %v:\n", plainText, cipherText)
	decryptedText, _ := DecryptByCBCMode(key, cipherText)
	fmt.Printf("Decrypted Text: %v\n ", decryptedText)

	plainText = "12345"
	cipherText, _ = EncryptByCBCMode(key, plainText) // 32byte

	fmt.Println()

	decryptedText, _ = DecryptByCBCMode(key, cipherText)
	fmt.Printf("Decrypted Text: %v\n ", decryptedText)

	fmt.Println()

	cipherText, _ = EncryptByGCM(key, "12345")
	fmt.Printf("Encrypted using GCM: %v\n", cipherText)
	decryptedText, _ = DecryptByGCM(key, cipherText)
	fmt.Printf("Decrypted Text: %v\n ", decryptedText)
	//plainText = "12345"
	//cipherText, _ = EncryptByCBCMode(key, plainText)
	//fmt.Printf("Plaintext %v is encrypted into %v:\n", plainText, cipherText)
	//decryptedText, _ = DecryptByCBCMode(key, cipherText)
	//fmt.Printf("Decrypted Text: %v\n ", decryptedText)
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


func PadByPkcs7(data []byte) []byte {
	padSize := aes.BlockSize
	if len(data) % aes.BlockSize != 0 {
		padSize = aes.BlockSize - (len(data)) % aes.BlockSize
	}

	pad := bytes.Repeat([]byte{byte(padSize)}, padSize)
	return append(data, pad...) // Dots represent it unpack Slice(pad) into individual bytes
}

func UnPadByPkcs7(data []byte) []byte {
	padSize := int(data[len(data) - 1])
	return data[:len(data) - padSize]
}

func EncryptByCBCMode(key []byte, plainText string) ([]byte, error) {
	block, err := aes.NewCipher(key); if err != nil {
		return nil, err
	}

	paddedPlaintext := PadByPkcs7([]byte(plainText))
	cipherText := make([]byte, len(paddedPlaintext)) // cipher text must be larger than plaintext
	iv := make([]byte, aes.BlockSize)// Unique iv is required
	_, err = rand.Read(iv); if err != nil {
		return nil, err
	}

	cbc := cipher.NewCBCEncrypter(block, iv)
	cbc.CryptBlocks(cipherText, paddedPlaintext)
	cipherText = append(iv, cipherText...)

	mac := hmac.New(sha256.New, []byte("12345678912345678912345678912345")) // sha256のhmac_key(32 byte)
	mac.Write(cipherText)
	cipherText = mac.Sum(cipherText)
	macSize := len(cipherText) - sha256.Size

	fmt.Println()
	fmt.Printf("PlainText: %v\n", plainText)
	fmt.Printf("Original Plain Text in byte format: %v\n", []byte(plainText))
	fmt.Printf("Padded Plain Text in byte format: %v\n", paddedPlaintext)
	fmt.Printf("MAC: %v\n", cipherText[macSize:])
	fmt.Printf("IV: %v\n", cipherText[:aes.BlockSize])
	fmt.Printf("Cipher Text: %v\n", cipherText[aes.BlockSize:macSize])

	return []byte(cipherText), nil
}

// GCM encryption
func EncryptByGCM(key []byte, plainText string) ([]byte, error) {
	block, err := aes.NewCipher(key); if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block); if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())// Unique nonce is required(NonceSize 12byte)
	_, err = rand.Read(nonce); if err != nil {
		return nil, err
	}

	cipherText := gcm.Seal(nil, nonce, []byte(plainText), nil)
	cipherText = append(nonce, cipherText...)

	return cipherText, nil
}

/**
	cipherText: PKCS#7 Pad + AES encrypted CipherText + SHA256 MAC Message
 */
func DecryptByCBCMode(key []byte, cipherText []byte) (string, error) {
	if len(cipherText) < aes.BlockSize + sha256.Size {
		panic("cipher text must be longer than blocksize")
	} else if len(cipherText) % aes.BlockSize != 0 {
		panic("cipher text must be multiple of blocksize(128bit)")
	}

	macSize := len(cipherText) - sha256.Size
	macMessage := cipherText[macSize:]
	mac := hmac.New(sha256.New, []byte("12345678912345678912345678912345")) // sha256のhmac_key(32 byte)
	mac.Write(cipherText[:macSize])
	expectedMAC := mac.Sum(nil)

	if !hmac.Equal(macMessage, expectedMAC) {
		return "", errors.New("Failed Decrypting")
	}

	iv := cipherText[:aes.BlockSize]
	plainText := make([]byte, len(cipherText[aes.BlockSize:macSize]))
	block, err := aes.NewCipher(key); if err != nil {
		return "", err
	}
	cbc := cipher.NewCBCDecrypter(block, iv)
	cbc.CryptBlocks(plainText, cipherText[aes.BlockSize:macSize])

	fmt.Printf("MAC: %v\n", macMessage)
	fmt.Printf("IV: %v\n", cipherText[:aes.BlockSize])
	fmt.Printf("Cipher Text: %v\n", cipherText[aes.BlockSize:macSize])

	return string(UnPadByPkcs7(plainText)), nil
}

func DecryptByGCM(key []byte, cipherText []byte) (string, error) {
	block, err := aes.NewCipher(key); if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block); if err != nil {
		return "", err
	}

	nonce := cipherText[:gcm.NonceSize()]
	plainByte, err := gcm.Open(nil, nonce, cipherText[gcm.NonceSize():], nil); if err != nil {
		return "", err
	}

	return string(plainByte), nil
}
