# go-encrypt

This project focuses on encrypting Personally Identifiable Information (PII) using the Go programming language.

## Features

- Encryption and decryption of PII data
- Easy integration with go applications

## Getting Started

To give Git credentials, you’ll need to have a .netrc that includes gitlab.playcourt.id in your home directory.

### Installation

```sh
go get github.com/dyaksa/encryption-pii@latest
```

### Upgrade or downgrade with tag version if available

```sh
go get github.com/dyaksa/encryption-pii@v.1.0.0
```

## Initialization

### To Give key credential .env

```sh
CRYPTO_AES_KEY=XXXXXXXXXXXXXXXXXXXXXXXXXXXX

CRYPTO_HMAC_KEY=XXXXXXXXXXXXXXXXXXXXXXXXXX
```

### To Give Key credential .env for Heap Database

```sh
CRYPTO_HEAP_DB_HOST=localhost
CRYPTO_HEAP_DB_PORT=5432
CRYPTO_HEAP_DB_USER=admin
CRYPTO_HEAP_DB_PASSWORD=password
CRYPTO_HEAP_DB_NAME=sandbox_pii
```

Import library

We need to create a new object by calling the `crypto.New`

```sh
func main() {
    crypto, err := crypto.New(
        crypto.Aes256KeySize,
        crypto.WithInitHeapConnection(),
    )
}
```

## Encrypt Data

### Define Struct Data

```sh
type Profile struct {
    Name    types.AESCipher
    Nik     types.AESCipher
    Phone   types.AESCipher
    Email   types.AESCipher
}
```

```sh
func main() {
    crypto, err := crypto.New(crypto.Aes256KeySize)

    profile := Profile {
        Name:   crypto.Encrypt("test", aesx.AesCBC)
        Nik:    crypto.Encrypt("123455", aesx.AesCBC)
        Phone   crypto.Encrypt("123455", aesx.AesCBC)
        Email   crypto.Encrypt("123455", aesx.AesCBC)
    }
}
```

## Example

for reference to the use of pii implementation can check ([Example](https://github.com/dyaksa/go_restapi))

## Authors

Dyaksa Jauharuddin Nour ([Github](https://github.com/dyaksa))
