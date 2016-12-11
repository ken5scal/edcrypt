package main

import (
	"crypto/aes"
	"fmt"
	"crypto/cipher"
	"crypto/rand"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
)

func main() {
	plainText := "1234123412341234"

	key := []byte("1234123412341234123412341234123") // Not AES-128, 256, 512(bit)
	fmt.Println(EncryptByBlockSecretKey(key, plainText))

	key = []byte("1234123412341234") // AES-128
	fmt.Println(EncryptByBlockSecretKey(key, "12341234123412345")) // Longer than 16 byte

	// This will result in Panic
	//fmt.Println(EncryptByBlockSecretKey(key, "123412341234123")) // Shorter than 16 byte

	//cipherText, _ := EncryptByBlockSecretKey(key, plainText)
	//fmt.Println(cipherText)
	//
	//plainText = DecryptByBlockSecretKey(key, cipherText)
	//fmt.Println(plainText)

	fmt.Println()

	//plainText = "1234567891234567"
	//cipherText, _ = EncryptByCBCMode(key, plainText) // 16bye
	//fmt.Printf("Plaintext %v is encrypted into %v:\n", plainText, cipherText)
	//decryptedText, _ := DecryptByCBCMode(key, cipherText)
	//fmt.Printf("Decrypted Text: %v\n ", decryptedText)

	fmt.Println()

	plainText = "12345678912345671234123412341234"
	cipherText, _ := EncryptByCBCMode(key, plainText) // 32byte
	decryptedText, _ := DecryptByCBCMode(key, cipherText)
	fmt.Printf("Decrypted Text: %v\n ", decryptedText)

	fmt.Println()

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
	fmt.Printf("Original Plain Text in byte format: %v\n", []byte(plainText))
	fmt.Printf("Padded Plain Text in byte format: %v\n", paddedPlaintext)
	cipherText := make([]byte, aes.BlockSize + len(paddedPlaintext)) // cipher text must be larger than plaintext
	iv := cipherText[:aes.BlockSize] // Unique iv is required
	_, err = rand.Read(iv); if err != nil {
		return nil, err
	}

	cbc := cipher.NewCBCEncrypter(block, iv)
	cbc.CryptBlocks(cipherText[aes.BlockSize:], paddedPlaintext)

	fmt.Printf("IV: %v\n",iv)
	fmt.Printf("Cipher Text With IV: %v\n",cipherText)

	mac := hmac.New(sha256.New, []byte("12345678912345678912345678912345")) // sha256のhmac_key(32 byte)
	mac.Write(cipherText)
	cipherText = mac.Sum(cipherText)

	fmt.Printf("Cipher Text Appended MAC: %v\n",cipherText)

	return []byte(cipherText), nil
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

func DecryptByCBCMode(key []byte, cipherText []byte) (string, error) {
	block, err := aes.NewCipher(key); if err != nil {
		return "", err
	}

	if len(cipherText) < aes.BlockSize {
		panic("cipher text must be longer than blocksize")
	} else if len(cipherText) % aes.BlockSize != 0 {
		panic("cipher text must be multiple of blocksize(128bit)")
	}
	iv := cipherText[:aes.BlockSize] // assuming iv is stored in the first block of ciphertext
	mac_message := cipherText[len(cipherText) - sha256.Size:]
	cipherText = cipherText[aes.BlockSize:len(cipherText) - sha256.Size]
	plainText := make([]byte, len(cipherText))

	mac := hmac.New(sha256.New, []byte("12345678912345678912345678912345")) // sha256のhmac_key(32 byte)
	mac.Write(cipherText)
	expectedMAC := mac.Sum(nil)
	fmt.Println(hmac.Equal(mac_message, expectedMAC))

	cbc := cipher.NewCBCDecrypter(block, iv)
	cbc.CryptBlocks(plainText, cipherText)
	return string(UnPadByPkcs7(plainText)), nil
}
