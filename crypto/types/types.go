package types

import (
	"github.com/dyaksa/encryption-pii/crypto/aesx"
	"github.com/dyaksa/encryption-pii/crypto/core"
	"github.com/dyaksa/encryption-pii/crypto/hmacx"
)

type (
	AESChiper = aesx.AES[string, core.PrimitiveAES]
	HMACHash  = hmacx.HMAC[string, core.PrimitiveHMAC]
)
