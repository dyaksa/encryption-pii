package crypt

import (
	"context"
	"database/sql"
	"regexp"
	"strings"
	"time"

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

	cmd, err := l.initCMD()
	if err != nil {
		return nil, err
	}

	l.deriverKey, err = uuid.Parse(cmd.DeriverKey)
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

func (l *Lib) AEADByteArray(param []byte) sqlval.AEAD[[]byte, crypt.PrimitiveAEAD] {
	return sqlval.AEADByteArray(l.AEAD(), param, l.deriverKey[:])
}

func (l *Lib) ByteToArray() sqlval.AEAD[[]byte, crypt.PrimitiveAEAD] {
	return l.AEADByteArray([]byte{})
}

func (l *Lib) AEADString(param string) sqlval.AEAD[string, crypt.PrimitiveAEAD] {
	return sqlval.AEADString(l.AEAD(), param, l.deriverKey[:])
}

func (l *Lib) BToString() sqlval.AEAD[string, crypt.PrimitiveAEAD] {
	return l.AEADString("")
}

func (l *Lib) AEADTime(param time.Time) sqlval.AEAD[time.Time, crypt.PrimitiveAEAD] {
	return sqlval.AEADTime(l.AEAD(), param, l.deriverKey[:])
}

func (l *Lib) BToTime() sqlval.AEAD[time.Time, crypt.PrimitiveAEAD] {
	return l.AEADTime(time.Time{})
}

func (l *Lib) AEADBool(param bool) sqlval.AEAD[bool, crypt.PrimitiveAEAD] {
	return sqlval.AEADBool(l.AEAD(), param, l.deriverKey[:])
}

func (l *Lib) BToBool() sqlval.AEAD[bool, crypt.PrimitiveAEAD] {
	return l.AEADBool(false)
}

func (l *Lib) AEADFloat64(param float64) sqlval.AEAD[float64, crypt.PrimitiveAEAD] {
	return sqlval.AEADFloat64(l.AEAD(), param, l.deriverKey[:])
}

func (l *Lib) BToFloat64() sqlval.AEAD[float64, crypt.PrimitiveAEAD] {
	return l.AEADFloat64(0)
}

func (l *Lib) AEADInt64(param int64) sqlval.AEAD[int64, crypt.PrimitiveAEAD] {
	return sqlval.AEADInt64(l.AEAD(), param, l.deriverKey[:])
}

func (l *Lib) BToInt64() sqlval.AEAD[int64, crypt.PrimitiveAEAD] {
	return l.AEADInt64(0)
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

type FindTextHeapByContentParams struct {
	Content string
}

func (l *Lib) SearchContents(ctx context.Context, tx *sql.Tx, column string, args func(FindTextHeapByContentParams) (bool, error)) (heaps []string, err error) {
	var query = new(strings.Builder)
	query.WriteString("SELECT content FROM ")
	query.WriteString(column)
	query.WriteString(" WHERE content ILIKE $1")
	var rows *sql.Rows
	var arg FindTextHeapByContentParams
	if args != nil {
		if ok, _ := args(arg); !ok {
			return
		}
	}
	rows, err = tx.QueryContext(ctx, query.String(), arg.Content)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var i FindTextHeapRow
		err = rows.Scan(&i.Content)
		if err != nil {
			return
		}
		heaps = append(heaps, i.Content)
	}
	return
}

func (l *Lib) BuildHeap(value string, typeHeap string) (s string, th []TextHeap) {
	var values = split(value)
	builder := new(strings.Builder)
	for _, value := range values {
		builder.WriteString(l.HMACString(value).HashString())
		th = append(th, TextHeap{
			Content: strings.ToLower(value),
			Type:    typeHeap,
			Hash:    l.HMACString(value),
		})
	}
	return builder.String(), th
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
