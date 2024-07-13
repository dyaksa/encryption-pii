package crypt

import (
	"context"
	"database/sql"
	"regexp"
	"strings"

	"github.com/dyaksa/encryption-pii/cmd"
	"github.com/dyaksa/encryption-pii/crypt"
	"github.com/dyaksa/encryption-pii/crypt/sqlval"
	"github.com/dyaksa/encryption-pii/crypt/types"
	"github.com/google/uuid"
)

type TextHeap struct {
	Content string
	Type    string
	Hash    types.HMACString
}

type Lib struct {
	deriverKey uuid.UUID
	aead       *crypt.DerivableKeyset[crypt.PrimitiveAEAD]
	bidx       *crypt.DerivableKeyset[crypt.PrimitiveBIDX]
	hmac       *crypt.DerivableKeyset[crypt.PrimitiveHMAC]
}

func New() (l *Lib, err error) {
	l = &Lib{}

	l.deriverKey, err = uuid.Parse("c2aaf7c8-50b5-435f-9a6a-fe1f22ce2d82")
	if err != nil {
		return nil, err
	}

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

	l.hmac, err = cmd.HMACDerivableKeyset()
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

func (l *Lib) HMACFunc(id uuid.UUID) func() (crypt.PrimitiveHMAC, error) {
	return l.hmac.GetPrimitiveFunc(id[:])
}

func (l *Lib) AEAD() func() (crypt.PrimitiveAEAD, error) {
	return l.AEADFunc(l.deriverKey)
}

func (l *Lib) BIDX() func() (crypt.PrimitiveBIDX, error) {
	return l.BIDXFunc(l.deriverKey)
}

func (l *Lib) HMAC() func() (crypt.PrimitiveHMAC, error) {
	return l.HMACFunc(l.deriverKey)
}

func (l *Lib) AEADString(param string) sqlval.AEAD[string, crypt.PrimitiveAEAD] {
	return sqlval.AEADString(l.AEAD(), param, l.deriverKey[:])
}

func (l *Lib) BIDXString(param string) sqlval.BIDX[string, crypt.PrimitiveBIDX] {
	return sqlval.BIDXString(l.BIDX(), param)
}

func (l *Lib) HMACString(param string) sqlval.HMAC[string, crypt.PrimitiveHMAC] {
	return sqlval.HMACString(l.HMAC(), param)
}

func (l *Lib) SaveToHeap(ctx context.Context, tx *sql.Tx, textHeaps []TextHeap) (err error) {
	for _, th := range textHeaps {
		query := new(strings.Builder)
		query.WriteString("INSERT INTO ")
		query.WriteString(th.Type)
		query.WriteString(" (content, hash) VALUES ($1, $2)")
		if ok, _ := isHashExist(ctx, tx, th.Type, FindTextHeapByHashParams{Hash: th.Hash.HashString()}); !ok {
			_, err = tx.ExecContext(ctx, query.String(), th.Content, th.Hash.HashString())
		}
	}

	return
}

type FindTextHeapByHashParams struct {
	Hash string
}

type FindTextHeapRow struct {
	ID      uuid.UUID
	Content string
	Hash    string
}

func isHashExist(ctx context.Context, tx *sql.Tx, typeHeap string, args FindTextHeapByHashParams) (bool, error) {
	var query = new(strings.Builder)
	query.WriteString("SELECT hash FROM ")
	query.WriteString(typeHeap)
	query.WriteString(" WHERE hash = $1")
	row := tx.QueryRowContext(ctx, query.String(), args.Hash)
	var i FindTextHeapRow
	err := row.Scan(&i.Hash)
	if err != nil {
		return false, err
	}
	if i.Hash == args.Hash {
		return true, nil
	}
	return false, nil
}

func (l *Lib) BuildHeap(value string, typeHeap string) (s string, th []TextHeap) {
	var values = split(value)
	builder := new(strings.Builder)
	for _, value := range values {
		builder.WriteString(l.HMACString(value).HashString())
		th = append(th, TextHeap{
			Content: value,
			Type:    typeHeap,
			Hash:    l.HMACString(value),
		})
	}
	return builder.String(), th
}

func split(value string) (s []string) {
	var sep = " "
	reg := "[a-zA-Z0-9]+"
	regex := regexp.MustCompile(reg)
	if validateEmail(value) {
		sep = "@"
	}
	parts := strings.Split(value, sep)
	for _, part := range parts {
		matches := regex.FindAllString(part, -1)
		s = append(s, matches...)
	}

	return
}

func validateEmail(email string) bool {
	// Define the email regex pattern
	const emailRegexPattern = `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`

	// Compile the regex pattern
	re := regexp.MustCompile(emailRegexPattern)

	// Match the input email with the regex pattern
	return re.MatchString(email)
}
