package postgres

import (
	"context"

	"github.com/dyaksa/sqlx-encrypt/crypt/sqlval"
	"github.com/dyaksa/sqlx-encrypt/postgres/internal/sqlc"
	"github.com/dyaksa/sqlx-encrypt/profile"
)

func (p *Postgres) StoreProfile(ctx context.Context, pr *profile.Profile) (err error) {
	tx, errTx := p.DB.BeginTx(ctx, nil)
	if errTx != nil {
		return errTx
	}

	query := p.q.WithTx(tx)
	err = query.StoreProfile(ctx, sqlc.StoreProfileParams{
		ID:        pr.ID,
		Nik:       sqlval.AEADString(p.AEADFunc(pr.ID), pr.Nik, pr.ID[:]),
		NikBidx:   sqlval.BIDXString(p.BIDXFunc(pr.ID), pr.Nik),
		Name:      sqlval.AEADString(p.AEADFunc(pr.ID), pr.Name, pr.ID[:]),
		NameBidx:  sqlval.BIDXString(p.BIDXFunc(pr.ID), pr.Name),
		Phone:     sqlval.AEADString(p.AEADFunc(pr.ID), pr.Phone, pr.ID[:]),
		PhoneBidx: sqlval.BIDXString(p.BIDXFunc(pr.ID), pr.Phone),
		Email:     sqlval.AEADString(p.AEADFunc(pr.ID), pr.Email, pr.ID[:]),
		EmailBidx: sqlval.BIDXString(p.BIDXFunc(pr.ID), pr.Email),
		Dob:       sqlval.AEADTime(p.AEADFunc(pr.ID), pr.DOB, pr.ID[:]),
	})

	if err != nil {
		tx.Rollback()
		return
	}

	if err = tx.Commit(); err != nil {
		return
	}

	return
}
