package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/tink-crypto/tink-go/tink"
)

type Outbox struct {
	ID          uuid.UUID `json:"id"`
	TenantID    uuid.UUID `json:"tenant_id"`
	ContentType string    `json:"content_type"`
	CreatedAt   time.Time `json:"created_at"`
	Event       string    `json:"event"`
	Content     any       `json:"content"`
	IsEncrypted bool      `json:"is_encrypted"`

	aead        tink.AEAD
	contentByte []byte
}

func newOutbox(tid uuid.UUID, event string, ctype string, content any) (o *Outbox, err error) {
	o = &Outbox{
		TenantID:    tid,
		Event:       event,
		ContentType: ctype,
		CreatedAt:   time.Now(),
		Content:     content,
	}

	o.ID, err = uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("failed to generate uuid: %w", err)
	}
	return
}

func (p *Postgres) newOutbox(tid uuid.UUID, event, ctype string, content any) (o *Outbox, err error) {
	o, err = newOutbox(tid, event, ctype, content)
	if err != nil {
		return nil, fmt.Errorf("failed to create outbox: %w", err)
	}

	o.aead, err = p.aead.GetPrimitive(o.TenantID[:])
	if err != nil {
		return
	}

	return
}

func (p *Postgres) NewOutBoxEncrypt(tid uuid.UUID, event, ctype string, content any) (o *Outbox, err error) {
	o, err = p.newOutbox(tid, event, ctype, content)
	if err != nil {
		return
	}

	*o, err = o.AsEncrypted()

	return
}

func (ob Outbox) AsEncrypted() (o Outbox, err error) {
	if ob.IsEncrypted {
		return ob, nil
	}

	if ob.aead == nil {
		return o, fmt.Errorf("aead is not initialized")
	}

	b, err := json.Marshal(ob.Content)
	if err != nil {
		return o, fmt.Errorf("failed to marshal content: %w", err)
	}

	ob.Content, err = ob.aead.Encrypt(b, ob.ID[:])
	if err != nil {
		return o, fmt.Errorf("failed to encrypt content: %w", err)
	}

	ob.IsEncrypted = true

	return ob, nil
}

func (p *Postgres) StoreOutbox(ctx context.Context, tx *sqlx.Tx, ob *Outbox) (err error) {
	content, err := json.Marshal(ob.Content)
	if err != nil {
		return fmt.Errorf("failed to marshal content: %w", err)
	}

	outboxQ := `INSERT INTO outbox (id, tenant_id, content_type, created_at, event, content, is_encrypted) VALUES ($1, $2, $3, $4, $5, $6, $7)`

	_, err = tx.ExecContext(ctx, outboxQ, ob.ID, ob.TenantID, ob.ContentType, ob.CreatedAt, ob.Event, content, ob.IsEncrypted)

	if err != nil {
		return fmt.Errorf("failed to insert outbox: %w", err)
	}

	return
}
