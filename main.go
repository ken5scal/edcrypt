package main

import (
	"crypto/aes"
	"fmt"
	"crypto/cipher"
	"crypto/rand"
	"bytes"
)

func main() {
	plainText := "1234123412341234"

	key := []byte("1234123412341234123412341234123") // Not AES-128, 256, 512(bit)
	fmt.Println(EncryptByBlockSecretKey(key, plainText))

	key = []byte("1234123412341234") // AES-128
	fmt.Println(EncryptByBlockSecretKey(key, "12341234123412345")) // Longer than 16 byte

	// This will result in Panic
	// fmt.Println(EncryptByBlockSecretKey(key, "123412341234123")) // Shorter than 16 byte

	cipherText, _ := EncryptByBlockSecretKey(key, plainText)
	fmt.Println(cipherText)

	plainText = DecryptByBlockSecretKey(key, cipherText)
	fmt.Println(plainText)

	cipherText, _ = EncryptByCBCMode(key, "1234567891234567") // 16bye
	fmt.Println(cipherText)
	cipherText, _ = EncryptByCBCMode(key, "12345678912345671234123412341234") // 32byte
	fmt.Println(cipherText)

	plainText, _ = DecryptByCBCMode(key, cipherText)
	fmt.Println(plainText)

	cipherText, _ = EncryptByCBCMode(key, "123456781234567") // 16bye
	fmt.Println(cipherText)
	fmt.Println(DecryptByCBCMode(key, cipherText))
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
	padSize := len(data)
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
	//if len(plainText) % aes.BlockSize != 0 {
	//	panic("Plain text must be multiple of 128bit")
	//}

	block, err := aes.NewCipher(key); if err != nil {
		return nil, err
	}

	paddedPlaintext := PadByPkcs7([]byte(plainText))
	cipherText := make([]byte, aes.BlockSize + len(paddedPlaintext)) // cipher text must be larger than plaintext
	iv := cipherText[:aes.BlockSize] // Unique iv is required
	_, err = rand.Read(iv); if err != nil {
		return nil, err
	}

	cbc := cipher.NewCBCEncrypter(block, iv)
	cbc.CryptBlocks(cipherText[aes.BlockSize:], paddedPlaintext)

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
	cipherText = cipherText[aes.BlockSize:]
	plainText := make([]byte, len(cipherText))

	cbc := cipher.NewCBCDecrypter(block, iv)
	cbc.CryptBlocks(plainText, cipherText)
	fmt.Println(plainText)
	fmt.Println(UnPadByPkcs7(plainText))
	return string(UnPadByPkcs7(plainText)), nil
}


//# Padding
//現在だと、結局16の倍数にしか対応できていないので、そうでない平文をAESで暗号化するにはパディングをつけてやる必要がある。ただし、暗号文+パディングを繰り返し送ることで平文を一部推測できてしまう攻撃手法(パディングオラクル攻撃)があるので、復号しようとしている暗号文が正しいサブジェクトによって生成されたものかを認証することが必要になる(HMAC)。HMACは又今後書く。
//
//共通鍵方式のPaddingには以下の種類があるようだ(wiki調べ)
//* Bit Padding, Byte Padding, ANSI X.923, ISO 10126, PKCS#7, ISO/IEC 7816-4, Zero padding
//
//白状すると、各Paddingが何に適しているかはわからないし、調べる気力もなかった。ただPKCS #7は、RSA公開鍵方式で使われていたはずなので、信頼と実績でそれを使ってみようと思う。ただ、Goの場合は、Padding関係のパッケージが容易されてないので、自前実装することになる。~~メンドクサイ~~
//

