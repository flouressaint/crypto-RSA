package rsa

import (
	"crypto/rand"
	"math/big"
)

type RSA struct {
	PublicKey  *big.Int
	PrivateKey *big.Int
	N          *big.Int
}

func NewRSA(publicKey, privateKey, n *big.Int) *RSA {
	return &RSA{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
		N:          n,
	}
}

// generateKeys generates a pair of public and private keys based on the given number of bits.
//
// bits: the number of bits for the generated prime numbers.
// Returns three values: publicKey, privateKey, n.
func GenerateKeys(bits int) (*big.Int, *big.Int, *big.Int) {
	// Generate prime numbers
	p, _ := rand.Prime(rand.Reader, bits)
	q, _ := rand.Prime(rand.Reader, bits)

	// condition: p != q
	for p.Cmp(q) == 0 {
		q, _ = rand.Prime(rand.Reader, bits-1)
	}

	n := new(big.Int).Mul(p, q)

	// phi = (p - 1) * (q - 1)
	phi := new(big.Int).Mul(new(big.Int).Sub(p, big.NewInt(1)), new(big.Int).Sub(q, big.NewInt(1)))

	// generate publicKey
	publicKey := big.NewInt(2)
	for {
		// if gcd(publicKey, phi) == 1
		if new(big.Int).GCD(nil, nil, publicKey, phi).Cmp(big.NewInt(1)) == 0 {
			break
		}
		publicKey.Add(publicKey, big.NewInt(1))
	}

	// generate privateKey
	privateKey := big.NewInt(2)
	for {
		// if (privateKey * publicKey) % phi == 1
		if new(big.Int).Mod(new(big.Int).Mul(privateKey, publicKey), phi).Cmp(big.NewInt(1)) == 0 {
			break
		}
		privateKey.Add(privateKey, big.NewInt(1))
	}

	return publicKey, privateKey, n
}

// encrypt calculates the encryption of a given number using the provided public key and modulus.
//
// Parameters:
// - number: The number to be encrypted.
// - publicKey: The public key used for encryption.
// - n: The modulus.
//
// Returns:
// - The encrypted number.
func (rsa *RSA) Encrypt(number *big.Int) *big.Int {
	return new(big.Int).Exp(number, rsa.PublicKey, rsa.N)
}

// decrypt decrypts a number using the provided private key and modulus.
//
// Parameters:
// - number: the number to be decrypted.
// - privateKey: the private key used for decryption.
// - n: the modulus.
//
// Return:
// - decryptedNumber: the decrypted number.
func (rsa *RSA) Decrypt(number *big.Int) *big.Int {
	return new(big.Int).Exp(number, rsa.PrivateKey, rsa.N)
}

// encryptMessage takes a message string, a public key *big.Int, and an n *big.Int
// and returns an array of int64 values. Each int64 value is the encrypted representation
// of the corresponding character in the message string using the provided public key and n.
//
// Parameters:
// - message: The string message to be encrypted.
// - publicKey: The public key used for encryption.
// - n: The modulus used for encryption.
//
// Return Type:
// - []int64: An array of int64 values representing the encrypted message.
func (rsa *RSA) EncryptMessage(message string) []int64 {
	res := make([]int64, len(message))
	for i := 0; i < len(message); i++ {
		res[i] = rsa.Encrypt(big.NewInt(int64(message[i]))).Int64()
	}
	return res
}

// decryptMessage decrypts the given message using the provided private key and modulus.
//
// The function takes in three parameters:
//   - message: a slice of int64 representing the encrypted message
//   - privateKey: a pointer to a big.Int representing the private key
//   - n: a pointer to a big.Int representing the modulus
//
// The function returns a string representing the decrypted message.
func (rsa *RSA) DecryptMessage(message []int64) string {
	res := make([]byte, len(message))
	for i := 0; i < len(message); i++ {
		res[i] = byte(rsa.Decrypt(big.NewInt(message[i])).Int64())
	}
	return string(res)
}
