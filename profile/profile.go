package profile

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type Profile struct {
	ID    uuid.UUID
	Nik   string
	Name  string
	Phone string
	Email string
	DOB   time.Time
}

type ProfileRepository interface {
	StoreProfile(ctx context.Context, pr *Profile) (err error)
}
