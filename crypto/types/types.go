package types

import (
	"github.com/dyaksa/encryption-pii/crypto/aesx"
	"github.com/dyaksa/encryption-pii/crypto/core"
	"github.com/dyaksa/encryption-pii/crypto/hmacx"
)

type (
	AESCipher     = aesx.AES[string, core.PrimitiveAES]
	AESCipherJSON = aesx.AES[map[string]interface{}, core.PrimitiveAES]
	HMACHash      = hmacx.HMAC[string, core.PrimitiveHMAC]
)
