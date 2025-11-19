package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

const NONCE_LENGTH = 12

func Keccak256Hash(inputBytes []byte) common.Hash {
	return crypto.Keccak256Hash(inputBytes)
}

func DecryptAESGCM(encryptedData []byte, aesGcm cipher.AEAD) (*big.Int, error) {
	nonce := encryptedData[len(encryptedData)-NONCE_LENGTH:]
	ciphertext := encryptedData[:len(encryptedData)-NONCE_LENGTH]

	plaintext, err := aesGcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("Failed to decrypt: %v", err)
	}

	return new(big.Int).SetBytes(plaintext), nil
}

func CreateAESGCM(aesKey []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("Failed to create AES cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("Failed to create GCM: %v", err)
	}
	return gcm, nil
}
