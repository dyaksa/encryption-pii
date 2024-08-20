package crypto

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/dyaksa/encryption-pii/crypto/aesx"
	"github.com/dyaksa/encryption-pii/crypto/config"
	"github.com/dyaksa/encryption-pii/crypto/core"
	"github.com/dyaksa/encryption-pii/crypto/hmacx"
	_ "github.com/lib/pq"
)

type (
	AesKeySize int
)

const (
	Aes128KeySize AesKeySize = 16

	Aes192KeySize AesKeySize = 24

	Aes256KeySize AesKeySize = 32
)

func isValidKeySize(key []byte) bool {
	keySizes := []AesKeySize{Aes128KeySize, Aes192KeySize, Aes256KeySize}
	for _, keySize := range keySizes {
		if len(key) == int(keySize) {
			return true
		}
	}

	return false
}

type Opts func(*Crypto) error

func WithInitHeapConnection() Opts {
	return func(c *Crypto) error {
		dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
			*c.Host, *c.Port, *c.User, *c.Pass, *c.Name)
		db, err := sql.Open("postgres", dsn)
		if err != nil {
			return err
		}

		if err := db.Ping(); err != nil {
			return err
		}

		c.dbHeapPsql = db
		return nil
	}
}

type Crypto struct {
	AESKey  *string `env:"AES_KEY,expand" json:"aes_key"`
	HMACKey *string `env:"HMAC_KEY,expand" json:"hmac_key"`

	aes  *core.KeySet[core.PrimitiveAES]
	hmac *core.KeySet[core.PrimitiveHMAC]

	Host *string `env:"HEAP_DB_HOST" envDefault:"localhost" json:"db_host"`
	Port *string `env:"HEAP_DB_PORT" envDefault:"5432" json:"db_port"`
	User *string `env:"HEAP_DB_USER" envDefault:"user" json:"db_user"`
	Pass *string `env:"HEAP_DB_PASS" envDefault:"password" json:"db_pass"`
	Name *string `env:"HEAP_DB_NAME" envDefault:"dbname" json:"db_name"`

	dbHeapPsql *sql.DB

	keySize AesKeySize
}

func New(keySize AesKeySize, opts ...Opts) (c *Crypto, err error) {
	config := config.InitConfig()

	c = &Crypto{
		Host: &config.Host,
		Port: &config.Port,
		User: &config.User,
		Pass: &config.Pass,
		Name: &config.Name,

		AESKey:  &config.AesKey,
		HMACKey: &config.HmacKey,

		keySize: keySize,
	}

	// if err = c.initEnv(); err != nil {
	// 	return nil, err
	// }

	for _, opt := range opts {
		if err = opt(c); err != nil {
			return nil, err
		}
	}

	if c.AESKey == nil || c.HMACKey == nil {
		return nil, errors.New("key is required")
	}

	c.initAES()
	c.initHMAC()

	return c, nil
}

func (c *Crypto) InitHeapDatabase() (*sql.DB, error) {
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		*c.Host, *c.Port, *c.User, *c.Pass, *c.Name)
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		return nil, err
	}

	c.dbHeapPsql = db
	return db, nil
}

func (c *Crypto) initEnv() error {
	return envLoader(c, OptionsEnv{DotEnv: true, Prefix: "CRYPTO_"})
}

func (c *Crypto) initAES() {
	if c.AESKey == nil {
		c.aes = nil
	}

	a := core.NewInsecureKeyset([]byte(*c.AESKey), core.NewAEAS)
	c.aes = &a
}

func (c *Crypto) initHMAC() {
	if c.HMACKey == nil {
		c.hmac = nil
	}

	h := core.NewInsecureKeyset([]byte(*c.HMACKey), core.NewHMAC)
	c.hmac = &h
}

func (c *Crypto) AESFunc() func() (core.PrimitiveAES, error) {
	if !isValidKeySize([]byte(*c.AESKey)) {
		return func() (core.PrimitiveAES, error) {
			return core.PrimitiveAES{}, errors.New("invalid key size")
		}
	}

	return c.aes.GetPrimitiveFunc()
}

func (c *Crypto) Encrypt(data string, alg aesx.AesAlg) aesx.AES[string, core.PrimitiveAES] {
	return aesx.AESChiper(c.AESFunc(), data, alg)
}

func (c *Crypto) Decrypt(alg aesx.AesAlg) aesx.AES[string, core.PrimitiveAES] {
	return aesx.AESChiper(c.AESFunc(), "", alg)
}

func (c *Crypto) HMACFunc() func() (core.PrimitiveHMAC, error) {
	return c.hmac.GetPrimitiveFunc()
}

func (c *Crypto) Hash(data string) string {
	return hmacx.HMACHash(c.HMACFunc(), data).HashString()
}
