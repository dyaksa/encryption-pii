package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"
)

type (
	AlgHmac hash.Hash
)

var (
	SHA256 AlgHmac = hash.Hash(sha256.New())

	SHA384 AlgHmac = hash.Hash(sha512.New384())

	SHA512 AlgHmac = hash.Hash(sha512.New())
)

type Primitive interface {
	PrimitiveAES | PrimitiveHMAC
}

type NewPrimitive[T Primitive] func([]byte) (T, error)

type PrimitiveAES struct{ cipher.Block }

func NewAEAS(key []byte) (p PrimitiveAES, err error) {
	p.Block, err = aes.NewCipher(key)
	return
}

type PrimitiveHMAC struct{ hash.Hash }

func NewHMAC(key []byte) (p PrimitiveHMAC, err error) {
	if err = checkKeyLen(key); err != nil {
		return PrimitiveHMAC{}, err
	}
	p.Hash = hmac.New(sha256.New, key)
	return
}

const (
	minHmacKey                 = 32
	errorHmacKeyLenLessThanMin = "hmac key length not valid"
)

func checkKeyLen(key []byte) error {
	if len(key) < minHmacKey {
		return errors.New(errorHmacKeyLenLessThanMin)
	}

	return nil
}

type KeySet[T Primitive] struct {
	key         []byte
	constructur NewPrimitive[T]
}

func NewKeySet[T Primitive](key []byte, constructor NewPrimitive[T]) KeySet[T] {
	return KeySet[T]{
		key:         key,
		constructur: constructor,
	}
}

func NewInsecureKeyset[T Primitive](key []byte, constructor NewPrimitive[T]) KeySet[T] {
	return NewKeySet(key, constructor)
}

func (k *KeySet[T]) GetPrimitiveFunc() func() (T, error) {
	return func() (T, error) {
		return k.GetPrimitive()
	}
}

func (k *KeySet[T]) GetPrimitive() (T, error) {
	return k.constructur(k.key)
}

func (k *KeySet[T]) GetPrimitiveWithKeyFunc(key []byte) func() (T, error) {
	return func() (T, error) {
		return k.GetPrimitiveWithKey(key)
	}
}

func (k *KeySet[T]) GetPrimitiveWithKey(key []byte) (T, error) {
	return k.constructur(key)
}
