package main

import (
	"fmt"

	"github.com/flouressaint/crypto-RSA/rsa"
)

func main() {
	message := "Hello World!"
	fmt.Printf("Message: %s\n", message)

	publicKey, privateKey, n := rsa.GenerateKeys(5)

	rsa := rsa.NewRSA(publicKey, privateKey, n)

	encryptedMessage := rsa.EncryptMessage(message)
	fmt.Printf("Encrypted message: %v\n", encryptedMessage)

	decryptedMessage := rsa.DecryptMessage(encryptedMessage)
	fmt.Printf("Decrypted message: %s\n", decryptedMessage)
}
