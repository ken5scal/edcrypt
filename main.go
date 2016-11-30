package main

import (
	"crypto/aes"
	"fmt"
)

func main() {

	key := []byte("1234123412341234123412341234123") // Not AES-128, 256, 512(bit)
	c, err:= aes.NewCipher(key); if err != nil {
		fmt.Println(err.Error())
	}

	key = []byte("1234123412341234") // AES-128
	c, err = aes.NewCipher(key); if err != nil {
		fmt.Println(err.Error())
	}

	cipherText := make([]byte, aes.BlockSize)
	plainText := []byte("1234123412341234")

	c.Encrypt(cipherText, plainText) // Input/Output must be 16bits large
	fmt.Println(cipherText)

	c.Decrypt(plainText, cipherText)
	fmt.Println(string(plainText))
}