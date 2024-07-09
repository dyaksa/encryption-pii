package sqlval

import (
	"encoding/binary"
	"strings"
	"time"

	"github.com/dyaksa/encryption-pii/crypt"
)

func BIDX8DigitOutput[T any, B crypt.BIDX](f BIDXFunc[B], t T, converter func(T) ([]byte, error)) BIDX[T, B] {
	return BIDX[T, B]{
		bidxFunc: f,
		converter: func(t T) ([]byte, error) {
			b, err := converter(t)
			if err != nil {
				return nil, err
			}

			bidx, err := f()
			if err != nil {
				return nil, err
			}

			encrypted, err := bidx.ComputePrimary(b)
			if err != nil {
				return nil, err
			}
			encryptedStr := string(encrypted)

			if len(encryptedStr) < 8 {
				encryptedStr = strings.Repeat("0", 8-len(encryptedStr)) + encryptedStr
			}
			return []byte(encryptedStr[len(encryptedStr)-8:]), nil
		},
		isWrite: true,
		t:       t,
	}
}

func BIDXByteArray8Digit[B crypt.BIDX](f BIDXFunc[B], s []byte) BIDX[[]byte, B] {
	return BIDX8DigitOutput(f, s, func(s []byte) ([]byte, error) {
		return s, nil
	})
}

func BIDXString8Digit[B crypt.BIDX](f BIDXFunc[B], s string) BIDX[string, B] {
	return BIDX8DigitOutput(f, s, func(s string) ([]byte, error) {
		return []byte(s), nil
	})
}

func BIDXTime8Digit[B crypt.BIDX](f BIDXFunc[B], t time.Time) BIDX[time.Time, B] {
	return BIDX8DigitOutput(f, t, func(t time.Time) ([]byte, error) {
		return t.MarshalBinary()
	})
}

func BIDXBool8Digit[B crypt.BIDX](f BIDXFunc[B], t bool) BIDX[bool, B] {
	return BIDX8DigitOutput(f, t, func(t bool) ([]byte, error) {
		if !t {
			return []byte{0}, nil
		}
		return []byte{1}, nil
	})
}

func BIDXInt648Digit[B crypt.BIDX](f BIDXFunc[B], t int64) BIDX[int64, B] {
	return BIDX8DigitOutput(f, t, func(t int64) ([]byte, error) {
		b := make([]byte, 8)
		binary.LittleEndian.PutUint64(b, uint64(t))
		return b, nil
	})
}
