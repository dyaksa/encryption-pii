package types

import (
	"time"

	"github.com/dyaksa/encryption-pii/crypt"
	"github.com/dyaksa/encryption-pii/crypt/sqlval"
)

// type aliases so that it can be used by sqlc
type (
	AEADString  = sqlval.AEAD[string, crypt.PrimitiveAEAD]
	AEADBool    = sqlval.AEAD[bool, crypt.PrimitiveAEAD]
	AEADFloat64 = sqlval.AEAD[float64, crypt.PrimitiveAEAD]
	AEADTime    = sqlval.AEAD[time.Time, crypt.PrimitiveAEAD]
	AEADInt64   = sqlval.AEAD[int64, crypt.PrimitiveAEAD]
	BIDXString  = sqlval.BIDX[string, crypt.PrimitiveBIDX]
	HMACString  = sqlval.HMAC[string, crypt.PrimitiveHMAC]
)
