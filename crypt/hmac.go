package crypt

import (
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/mac"
	"github.com/tink-crypto/tink-go/v2/tink"
)

type HMAC interface {
	ComputePrimary(data []byte) (idx []byte, err error)
	Verify(data, idx []byte) (err error)
}

var _ HMAC = hmac{}

type hmac struct {
	m tink.MAC
}

func NewHMAC(h *keyset.Handle) (HMAC, error) {
	m, err := mac.New(h)
	if err != nil {
		return nil, err
	}
	return hmac{m: m}, nil
}

func (h hmac) ComputePrimary(data []byte) (idx []byte, err error) {
	return h.m.ComputeMAC(data)
}

func (h hmac) Verify(data, idx []byte) (err error) {
	return h.m.VerifyMAC(idx, data)
}
