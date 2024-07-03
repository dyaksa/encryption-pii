package postgres

import (
	"fmt"
	"time"

	"github.com/dyaksa/sqlx-encrypt/crypt"
	"github.com/dyaksa/sqlx-encrypt/postgres/internal/sqlc"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	_ "github.com/lib/pq"
)

type OptsFunc func(*Postgres) error

func WithConn(host, port, user, password, name string) OptsFunc {
	return func(p *Postgres) (err error) {
		p.host = host
		p.port = port
		p.user = user
		p.password = password
		p.dbName = name
		return
	}
}

func WithMaxConn(maxPool, minPool int) OptsFunc {
	return func(p *Postgres) (err error) {
		p.maxPool = maxPool
		p.minPool = minPool
		return
	}
}

type Postgres struct {
	q  *sqlc.Queries
	DB *sqlx.DB

	aead *crypt.DerivableKeyset[crypt.PrimitiveAEAD]
	bidx *crypt.DerivableKeyset[crypt.PrimitiveBIDX]

	host     string
	port     string
	user     string
	password string
	dbName   string

	maxPool int
	minPool int
}

func New(optsFunc ...OptsFunc) (p *Postgres, err error) {
	p = &Postgres{}

	for _, f := range optsFunc {
		if err = f(p); err != nil {
			return nil, err
		}
	}

	p.DB, err = sqlx.Connect("postgres", "host="+p.host+" port="+p.port+" user="+p.user+" password="+p.password+" dbname="+p.dbName+" sslmode=disable")
	if err != nil {
		return nil, fmt.Errorf("missing pg connection")
	}

	p.DB.SetMaxOpenConns(p.maxPool)
	p.DB.SetMaxIdleConns(p.minPool)
	p.DB.SetConnMaxLifetime(10 * time.Minute)

	p.aead, err = crypt.NewInsecureCleartextDerivableKeyset("aead.json", crypt.NewPrimitiveAEAD)
	if err != nil {
		return nil, fmt.Errorf("missing aead keyset")
	}

	p.bidx, err = crypt.NewInsecureCleartextDerivableKeyset("mac.json", crypt.NewPrimitiveBIDX)
	if err != nil {
		return nil, fmt.Errorf("missing bidx keyset")
	}

	p.q = sqlc.New(p.DB)

	if p.aead == nil || p.bidx == nil {
		return nil, fmt.Errorf("missing aead or bidx primitive")
	}

	return p, nil
}

func (p *Postgres) AEADFunc(id uuid.UUID) func() (crypt.PrimitiveAEAD, error) {
	return p.aead.GetPrimitiveFunc(id[:])
}

func (p *Postgres) BIDXFunc(id uuid.UUID) func() (crypt.PrimitiveBIDX, error) {
	return p.bidx.GetPrimitiveFunc(id[:])
}

func (p *Postgres) Close() error {
	return p.DB.Close()
}
