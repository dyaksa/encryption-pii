package crypt

import (
	"github.com/dyaksa/encryption-pii/cmd"
	"github.com/dyaksa/encryption-pii/crypt"
	"github.com/google/uuid"
)

type Lib struct {
	aead *crypt.DerivableKeyset[crypt.PrimitiveAEAD]
	bidx *crypt.DerivableKeyset[crypt.PrimitiveBIDX]
}

func New() (l *Lib, err error) {
	l = &Lib{}

	cmd, err := l.initCMD()
	if err != nil {
		return nil, err
	}

	l.aead, err = cmd.AEADDerivableKeyset()
	if err != nil {
		return nil, err
	}

	l.bidx, err = cmd.MACDerivableKeyset()
	if err != nil {
		return nil, err
	}

	return
}

func (l *Lib) initCMD() (*cmd.CMD, error) {
	cmd, err := cmd.New()
	if err != nil {
		return cmd, err
	}
	return cmd, nil
}

func (l *Lib) AEADFunc(id uuid.UUID) func() (crypt.PrimitiveAEAD, error) {
	return l.aead.GetPrimitiveFunc(id[:])
}

func (l *Lib) BIDXFunc(id uuid.UUID) func() (crypt.PrimitiveBIDX, error) {
	return l.bidx.GetPrimitiveFunc(id[:])
}
