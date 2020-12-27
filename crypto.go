/*
------------------------------------------------------------------------------------------------------------------------
####### crypto ####### (c) 2020-2021 mls-361 ####################################################### MIT License #######
------------------------------------------------------------------------------------------------------------------------
*/

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"

	"github.com/mls-361/failure"
)

type (
	// Crypto AFAIRE.
	Crypto struct {
		key []byte
	}
)

// New AFAIRE.
func New() *Crypto {
	return &Crypto{
		key: []byte{
			0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
			0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
		},
	}
}

// SetKey AFAIRE.
func (c *Crypto) SetKey(key string) error {
	hasher := sha256.New()

	_, err := hasher.Write([]byte(key))
	if err != nil {
		return err
	}

	c.key = hasher.Sum(nil)

	return nil
}

// Encrypt AFAIRE.
func (c *Crypto) Encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, data, nil), nil
}

// EncryptString AFAIRE.
func (c *Crypto) EncryptString(text string) (string, error) {
	data, err := c.Encrypt([]byte(text))
	if err != nil {
		return "", failure.New(err).
			Set("string", text).
			Msg("impossible to encrypt this string") ///////////////////////////////////////////////////////////////////
	}

	return base64.StdEncoding.EncodeToString(data), nil
}

// Decrypt AFAIRE.
func (c *Crypto) Decrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	nonce, cipherData := data[:nonceSize], data[nonceSize:]

	plainData, err := gcm.Open(nil, nonce, cipherData, nil)
	if err != nil {
		return nil, err
	}

	return plainData, nil
}

// DecryptString AFAIRE.
func (c *Crypto) DecryptString(text string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return "", failure.New(err).
			Set("string", text).
			Msg("impossible to decode this string") ////////////////////////////////////////////////////////////////////
	}

	data, err := c.Decrypt(decoded)
	if err != nil {
		return "", failure.New(err).
			Set("string", text).
			Msg("impossible to decrypt this string") ///////////////////////////////////////////////////////////////////
	}

	return string(data), nil
}

/*
######################################################################################################## @(°_°)@ #######
*/
