package tapo

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

type tpLinkCrypto struct {
	secret []byte
	iv     []byte
	block  *cipher.Block
}

func (c tpLinkCrypto) Encrypt(data []byte) []byte {
	paddedData := pad(data, 16)

	mode := cipher.NewCBCEncrypter(*c.block, c.iv)

	var ciphertext []byte

	mode.CryptBlocks(ciphertext, paddedData)

	return ciphertext
}

func (c tpLinkCrypto) Decrypt(ciphertext []byte) ([]byte, error) {
	mode := cipher.NewCBCDecrypter(*c.block, c.iv)
	var decryptedData []byte
	mode.CryptBlocks(decryptedData, ciphertext)
	return unpad(decryptedData)
}

func pad(input []byte, blockSize int) []byte {
	r := len(input) % blockSize
	pl := blockSize - r
	for i := 0; i < pl; i++ {
		input = append(input, byte(pl))
	}
	return input
}

func unpad(input []byte) ([]byte, error) {
	if input == nil || len(input) == 0 {
		return nil, nil
	}

	pc := input[len(input)-1]
	pl := int(pc)
	err := checkPaddingIsValid(input, pl)
	if err != nil {
		return nil, err
	}
	return input[:len(input)-pl], nil
}

func checkPaddingIsValid(input []byte, paddingLength int) error {
	if len(input) < paddingLength {
		return errors.New("invalid padding")
	}
	p := input[len(input)-(paddingLength):]
	for _, pc := range p {
		if uint(pc) != uint(len(p)) {
			return errors.New("invalid padding")
		}
	}
	return nil
}

func NewCrypto(key, iv []byte) (*tpLinkCrypto, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &tpLinkCrypto{
		secret: key,
		iv:     iv,
		block:  &block,
	}, nil

}
