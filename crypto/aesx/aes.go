package aesx

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"errors"
	"io"

	"github.com/dyaksa/encryption-pii/crypto/core"
)

type (
	AesAlg string
)

const (
	AesCBC AesAlg = "cbc"

	AesCFB AesAlg = "cfb"

	AesGCM AesAlg = "gcm"
)

func PKCS5Padding(plainText []byte) []byte {
	padding := (aes.BlockSize - len(plainText)%aes.BlockSize)
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(plainText, padtext...)
}

func PKCS5UnPadding(src []byte) ([]byte, error) {
	length := len(src)
	unpadding := int(src[length-1])
	unpadding = length - unpadding
	if unpadding < 0 {
		return nil, errors.New("invalid encrypted data or key")
	}
	return src[:unpadding], nil
}

func GenerateRandomIV(b []byte) error {
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return err
	}

	return nil
}

var _ interface {
	sql.Scanner
	driver.Value
} = &AES[any, cipher.Block]{}
var _ AESFunc[core.PrimitiveAES] = (*core.KeySet[core.PrimitiveAES])(nil).GetPrimitiveFunc()

type AESFunc[A cipher.Block] func() (A, error)

type AES[T any, A cipher.Block] struct {
	aesFunc AESFunc[A]
	btov    func(T) ([]byte, error)
	vtob    func([]byte) (T, error)

	v   T
	alg AesAlg
}

func (s AES[T, A]) Value() (driver.Value, error) {
	a, err := s.aesFunc()
	if err != nil {
		return nil, err
	}
	b, err := s.btov(s.v)
	if err != nil {
		return nil, err
	}

	switch s.alg {
	case AesCBC:
		plainDataPadded := PKCS5Padding(b)
		cipherDataBytes := make([]byte, len(plainDataPadded)+aes.BlockSize)

		err = GenerateRandomIV(cipherDataBytes[:aes.BlockSize])
		if err != nil {
			return nil, err
		}

		mode := cipher.NewCBCEncrypter(a, cipherDataBytes[:aes.BlockSize])
		mode.CryptBlocks(cipherDataBytes[aes.BlockSize:], plainDataPadded)

		dst := make([]byte, hex.EncodedLen(len(cipherDataBytes)))
		hex.Encode(dst, cipherDataBytes)

		return dst, nil
	case AesCFB:
		cipherDataBytes := make([]byte, len(b)+a.BlockSize())

		err = GenerateRandomIV(cipherDataBytes[:a.BlockSize()])
		if err != nil {
			return nil, err
		}

		stream := cipher.NewCFBEncrypter(a, cipherDataBytes[:a.BlockSize()])
		stream.XORKeyStream(cipherDataBytes[a.BlockSize():], b)

		dst := make([]byte, hex.EncodedLen(len(cipherDataBytes)))
		hex.Encode(dst, cipherDataBytes)

		return dst, nil
	case AesGCM:
		aesGCM, err := cipher.NewGCM(a)
		if err != nil {
			return nil, err
		}

		cipherDataBytes := make([]byte, len(b)+aesGCM.NonceSize())

		err = GenerateRandomIV(cipherDataBytes[:aesGCM.NonceSize()])
		if err != nil {
			return nil, err
		}

		res := aesGCM.Seal(nil, cipherDataBytes[:aesGCM.NonceSize()], b, nil)
		cipherDataBytes = append(cipherDataBytes[:aesGCM.NonceSize()], res...)

		dst := make([]byte, hex.EncodedLen(len(cipherDataBytes)))
		hex.Encode(dst, cipherDataBytes)

		return dst, nil
	}

	return nil, errors.New("invalid algorithm")
}

func (s *AES[T, A]) Scan(src any) (err error) {
	if src == nil {
		return
	}

	b, ok := src.([]byte)
	if !ok {
		return errors.New("not an encrypted byte")
	}

	a, err := s.aesFunc()
	if err != nil {
		return err
	}

	switch s.alg {
	case AesCBC:
		cipherDataBytes := make([]byte, hex.DecodedLen(len(b)))
		_, err = hex.Decode(cipherDataBytes, b)
		if err != nil {
			return err
		}

		iv := cipherDataBytes[:aes.BlockSize]
		cipherData := cipherDataBytes[aes.BlockSize:]

		if len(cipherData)%aes.BlockSize != 0 {
			return errors.New("cipher data is not a multiple of the block size")
		}

		mode := cipher.NewCBCDecrypter(a, iv)
		mode.CryptBlocks(cipherData, cipherData)
		plainData, err := PKCS5UnPadding(cipherData)
		if err != nil {
			return err
		}

		s.v, err = s.vtob(plainData)
		return err
	case AesCFB:
		cipherDataBytes := make([]byte, hex.DecodedLen(len(b)))
		_, err = hex.Decode(cipherDataBytes, b)
		if err != nil {
			return err
		}

		iv := cipherDataBytes[:a.BlockSize()]
		cipherData := cipherDataBytes[a.BlockSize():]

		stream := cipher.NewCFBDecrypter(a, iv)
		stream.XORKeyStream(cipherData, cipherData)

		s.v, err = s.vtob(cipherData)
		return err
	case AesGCM:
		cipherDataBytes := make([]byte, hex.DecodedLen(len(b)))

		_, err = hex.Decode(cipherDataBytes, b)
		if err != nil {
			return err
		}

		aesGCM, err := cipher.NewGCM(a)
		if err != nil {
			return err
		}

		nonceSize := aesGCM.NonceSize()
		if len(cipherDataBytes) < nonceSize {
			return errors.New("ciphertext too short")
		}

		nonce, cipherData := cipherDataBytes[:nonceSize], cipherDataBytes[nonceSize:]
		plainData, err := aesGCM.Open(nil, nonce, cipherData, nil)
		if err != nil {
			return err
		}

		s.v, err = s.vtob(plainData)
		return err
	}

	return errors.New("invalid algorithm")
}

func (s AES[T, A]) To() T {
	return s.v
}

func (s AES[T, A]) ToP() *T {
	return &s.v
}

func AESChiper[A cipher.Block](aesFunc AESFunc[A], data string, alg AesAlg) AES[string, A] {
	return AES[string, A]{
		aesFunc: aesFunc,
		btov: func(s string) ([]byte, error) {
			return []byte(s), nil
		},
		vtob: func(b []byte) (string, error) {
			return string(b), nil
		},
		alg: alg,
		v:   data,
	}
}
