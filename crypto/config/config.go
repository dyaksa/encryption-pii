package config

import (
	"os"

	"github.com/joho/godotenv"
)

func init() {
	godotenv.Load()
}

const (
	AesKey  = "CRYPTO_AES_KEY"
	HmacKey = "CRYPTO_HMAC_KEY"

	Host = "CRYPTO_HEAP_DB_HOST"
	Port = "CRYPTO_HEAP_DB_PORT"
	User = "CRYPTO_HEAP_DB_USER"
	Pass = "CRYPTO_HEAP_DB_PASS"
	Name = "CRYPTO_HEAP_DB_NAME"
)

type Config struct {
	AesKey  string
	HmacKey string

	Host string
	Port string
	User string
	Pass string
	Name string
}

func getEnv(key string) string {
	return os.Getenv(key)
}

func InitConfig() *Config {
	return &Config{
		AesKey:  getEnv(AesKey),
		HmacKey: getEnv(HmacKey),

		Host: getEnv(Host),
		Port: getEnv(Port),
		User: getEnv(User),
		Pass: getEnv(Pass),
		Name: getEnv(Name),
	}
}
