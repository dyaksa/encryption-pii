package hmacx

import (
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"hash"

	"github.com/dyaksa/encryption-pii/crypto/core"
)

var _ interface {
	sql.Scanner
	driver.Value
} = &HMAC[any, hash.Hash]{}
var _ HmacFunc[core.PrimitiveHMAC] = (*core.KeySet[core.PrimitiveHMAC])(nil).GetPrimitiveFunc()

type HmacFunc[h hash.Hash] func() (h, error)

type HMAC[T any, H hash.Hash] struct {
	hmacFunc HmacFunc[H]
	btov     func(T) ([]byte, error)
	vtob     func([]byte) (T, error)

	v T
}

func (h HMAC[T, H]) HashString() (str string) {
	m, err := h.hmacFunc()
	if err != nil {
		return ""
	}

	b, err := h.btov(h.v)
	if err != nil {
		return ""
	}

	_, err = m.Write(b)
	if err != nil {
		return ""
	}

	str = fmt.Sprintf("%x", m.Sum(nil))
	if len(str) > 8 {
		return str[len(str)-8:]
	}

	return str
}

func (h HMAC[T, H]) Value() (driver.Value, error) {
	m, err := h.hmacFunc()
	if err != nil {
		return nil, err
	}

	b, err := h.btov(h.v)
	if err != nil {
		return nil, err
	}

	_, err = m.Write(b)
	if err != nil {
		return nil, err
	}

	return m.Sum(nil), nil
}

func (h *HMAC[T, H]) Scan(value interface{}) error {
	if value == nil {
		return nil
	}

	b, ok := value.([]byte)
	if !ok {
		return errors.New("invalid type")
	}

	v, err := h.vtob(b)
	if err != nil {
		return err
	}

	h.v = v
	return nil
}

func HMACHash[H hash.Hash](hmacFunc HmacFunc[H], data string) HMAC[string, H] {
	return HMAC[string, H]{
		hmacFunc: hmacFunc,
		btov:     func(v string) ([]byte, error) { return []byte(v), nil },
		vtob:     func(b []byte) (string, error) { return string(b), nil },
		v:        data,
	}
}

type To[T any, H hash.Hash] struct {
	b []byte
}

func (h HMAC[T, H]) Hash() To[T, H] {
	t := To[T, H]{}
	m, err := h.hmacFunc()
	if err != nil {
		return t
	}

	b, err := h.btov(h.v)
	if err != nil {
		return t
	}

	_, err = m.Write(b)
	if err != nil {
		return t
	}

	t.b = m.Sum(nil)
	return t
}

func (t To[T, H]) ToString() string {
	return fmt.Sprintf("%x", t.b)
}

func (t To[T, H]) ToBytes() []byte {
	return t.b
}

func (t To[T, H]) ToLast8DigitValue() string {
	str := fmt.Sprintf("%x", t.b)
	if len(str) > 8 {
		return str[len(str)-8:]
	}

	return str
}

func Hash(data string, key []byte) (string, error) {
	h, err := core.NewHMAC(key)
	if err != nil {
		return "", err
	}

	h.Hash.Write([]byte(data))

	return fmt.Sprintf("%x", h.Hash.Sum(nil)), nil
}
