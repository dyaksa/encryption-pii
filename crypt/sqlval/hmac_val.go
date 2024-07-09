package sqlval

import (
	"fmt"

	"github.com/dyaksa/encryption-pii/crypt"
)

type HMACFunc[B crypt.HMAC] func() (B, error)

type HMAC[T any, B crypt.HMAC] struct {
	hmacFunc HMACFunc[B]
	btov     func(T) ([]byte, error)
	b        []byte
	isNil    bool
	v        T
}

func (s HMAC[T, H]) Hash() []byte {
	m, err := s.hmacFunc()
	if err != nil {
		return nil
	}

	s.b, err = s.btov(s.v)
	if err != nil {
		return nil
	}

	fullHMAC, err := m.ComputePrimary(s.b)
	if err != nil {
		return nil
	}

	if len(fullHMAC) >= 8 {
		return fullHMAC[len(fullHMAC)-8:]
	} else {
		return fullHMAC
	}
}

func (s *HMAC[T, H]) Verify(src []byte) (err error) {
	if s.isNil {
		return
	}

	m, err := s.hmacFunc()
	if err != nil {
		return fmt.Errorf("fail to obtain HMAC primitive: %w", err)
	}

	s.b, err = s.btov(s.v)
	if err != nil {
		return fmt.Errorf("fail to convert to byte: %w", err)
	}

	return m.Verify(s.b, src)
}

func (s *HMAC[T, H]) To() T {
	return s.v
}

func (s *HMAC[T, H]) ToP() *T {
	if s.isNil {
		return nil
	}
	return &s.v
}

func NewHMAC[T any, H crypt.HMAC](hmacFunc HMACFunc[H], v T, btov func(T) ([]byte, error)) HMAC[T, H] {
	return HMAC[T, H]{
		hmacFunc: hmacFunc,
		v:        v,
		btov:     btov,
	}
}

func HMACByteArray[H crypt.HMAC](hmacFunc HMACFunc[H], b []byte) HMAC[[]byte, H] {
	return HMAC[[]byte, H]{
		hmacFunc: hmacFunc,
		v:        b,
		btov:     func(b []byte) ([]byte, error) { return b, nil },
	}
}

func HMACString[H crypt.HMAC](hmacFunc HMACFunc[H], s string) HMAC[string, H] {
	return HMAC[string, H]{
		hmacFunc: hmacFunc,
		v:        s,
		btov:     func(s string) ([]byte, error) { return []byte(s), nil },
	}
}

func HMACTime[H crypt.HMAC](hmacFunc HMACFunc[H], t string) HMAC[string, H] {
	return HMAC[string, H]{
		hmacFunc: hmacFunc,
		v:        t,
		btov:     func(s string) ([]byte, error) { return []byte(s), nil },
	}
}

func HMACBool[H crypt.HMAC](hmacFunc HMACFunc[H], b bool) HMAC[bool, H] {
	return HMAC[bool, H]{
		hmacFunc: hmacFunc,
		v:        b,
		btov:     func(b bool) ([]byte, error) { return []byte(fmt.Sprintf("%t", b)), nil },
	}
}

func HMACInt64[H crypt.HMAC](hmacFunc HMACFunc[H], i int64) HMAC[int64, H] {
	return HMAC[int64, H]{
		hmacFunc: hmacFunc,
		v:        i,
		btov:     func(i int64) ([]byte, error) { return []byte(fmt.Sprintf("%d", i)), nil },
	}
}

func HMACFloat64[H crypt.HMAC](hmacFunc HMACFunc[H], f float64) HMAC[float64, H] {
	return HMAC[float64, H]{
		hmacFunc: hmacFunc,
		v:        f,
		btov:     func(f float64) ([]byte, error) { return []byte(fmt.Sprintf("%f", f)), nil },
	}
}
