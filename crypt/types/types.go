package types

import (
	"time"

	"github.com/dyaksa/encryption-pii/crypt"
	"github.com/dyaksa/encryption-pii/crypt/sqlval"
)

// type aliases so that it can be used by sqlc
type (
	AEADString    = sqlval.AEAD[string, crypt.PrimitiveAEAD]
	AEADBool      = sqlval.AEAD[bool, crypt.PrimitiveAEAD]
	AEADFloat64   = sqlval.AEAD[float64, crypt.PrimitiveAEAD]
	AEADTime      = sqlval.AEAD[time.Time, crypt.PrimitiveAEAD]
	BIDXString    = sqlval.BIDX[string, crypt.PrimitiveBIDX]
	HMACString    = sqlval.HMAC[string, crypt.PrimitiveHMAC]
	HMACBool      = sqlval.HMAC[bool, crypt.PrimitiveHMAC]
	HMACFloat64   = sqlval.HMAC[float64, crypt.PrimitiveHMAC]
	HMACTime      = sqlval.HMAC[time.Time, crypt.PrimitiveHMAC]
	HMACInt64     = sqlval.HMAC[int64, crypt.PrimitiveHMAC]
	HMACByteArray = sqlval.HMAC[[]byte, crypt.PrimitiveHMAC]
)
