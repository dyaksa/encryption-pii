package crypto

import (
	"errors"

	"github.com/dyaksa/encryption-pii/cmd"
	"github.com/dyaksa/encryption-pii/crypto/aesx"
	"github.com/dyaksa/encryption-pii/crypto/core"
	"github.com/dyaksa/encryption-pii/crypto/hmacx"
)

type (
	AesKeySize int
)

const (
	Aes128KeySize AesKeySize = 16

	Aes192KeySize AesKeySize = 24

	Aes256KeySize AesKeySize = 32
)

func isValidKeySize(key []byte) bool {
	keySizes := []AesKeySize{Aes128KeySize, Aes192KeySize, Aes256KeySize}
	for _, keySize := range keySizes {
		if len(key) == int(keySize) {
			return true
		}
	}

	return false
}

type Crypto struct {
	AESKey  *string `env:"AES_KEY,expand" json:"aes_key"`
	HMACKey *string `env:"HMAC_KEY,expand" json:"hmac_key"`

	aes  *core.KeySet[core.PrimitiveAES]
	hmac *core.KeySet[core.PrimitiveHMAC]

	keySize AesKeySize
}

func New(keySize AesKeySize) (c *Crypto, err error) {
	c = &Crypto{
		keySize: keySize,
	}

	if err = c.initEnv(); err != nil {
		return nil, err
	}

	if c.AESKey == nil || c.HMACKey == nil {
		return nil, errors.New("key is required")
	}

	c.initAES()
	c.initHMAC()

	return c, nil
}

func (c *Crypto) initEnv() error {
	return cmd.EnvLoader(c, cmd.OptionsEnv{DotEnv: true, Prefix: "CRYPTO_"})
}

func (c *Crypto) initAES() {
	if c.AESKey == nil {
		c.aes = nil
	}

	a := core.NewInsecureKeyset([]byte(*c.AESKey), core.NewAEAS)
	c.aes = &a
}

func (c *Crypto) initHMAC() {
	if c.HMACKey == nil {
		c.hmac = nil
	}

	h := core.NewInsecureKeyset([]byte(*c.HMACKey), core.NewHMAC)
	c.hmac = &h
}

func (c *Crypto) AESFunc() func() (core.PrimitiveAES, error) {
	if !isValidKeySize([]byte(*c.AESKey)) {
		return func() (core.PrimitiveAES, error) {
			return core.PrimitiveAES{}, errors.New("invalid key size")
		}
	}

	return c.aes.GetPrimitiveFunc()
}

func (c *Crypto) Encrypt(data string, alg aesx.AesAlg) aesx.AES[string, core.PrimitiveAES] {
	return aesx.AESChiper(c.AESFunc(), data, alg)
}

func (c *Crypto) Decrypt(data string, alg aesx.AesAlg) aesx.AES[string, core.PrimitiveAES] {
	return aesx.AESChiper(c.AESFunc(), data, alg)
}

func (c *Crypto) HMACFunc() func() (core.PrimitiveHMAC, error) {
	return c.hmac.GetPrimitiveFunc()
}

func (c *Crypto) Hash(data string) string {
	return hmacx.HMACHash(c.HMACFunc(), data).HashString()
}
