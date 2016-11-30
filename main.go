package main

import (
	"crypto/aes"
	"fmt"
)

func main() {
	cipherText := make([]byte, aes.BlockSize)
	plainText := []byte("1234123412341234")
	key := []byte("12341234123412341234123412341234") // AES-256(bit)
	c, err:= aes.NewCipher(key); if err != nil {
		fmt.Println(err.Error())
		return
	}
	c.Encrypt(cipherText, plainText)
	fmt.Println(cipherText)

	c.Decrypt(plainText, cipherText)
	fmt.Println(string(plainText))
}