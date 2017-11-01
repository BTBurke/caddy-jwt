package jwt

import (
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
)

const ENV_PUBLIC_KEY = "JWT_PUBLIC_KEY"
const ENV_SECRET = "JWT_SECRET"

// KeyBackend provides a generic interface for providing key material for HS, RS, and ES algorithms
type KeyBackend interface {
	ProvideKey(token *jwt.Token) (interface{}, error)
}

// LazyPublicKeyBackend contains state to manage lazy key loading for RS and ES family algorithms
type LazyPublicKeyBackend struct {
	filename  string
	modTime   time.Time
	publicKey interface{}
}

// NewLazyPublicKeyFileBackend returns a new LazyPublicKeyBackend
func NewLazyPublicKeyFileBackend(value string) (*LazyPublicKeyBackend, error) {
	if len(value) <= 0 {
		return nil, fmt.Errorf("empty filename for public key provided")
	}
	return &LazyPublicKeyBackend{
		filename: value,
	}, nil
}

// ProvideKey will lazily load a secret key in a file, using a cached value if the key
// material has not changed.  An error is returned if the token does not match the
// expected signing algorithm.
func (instance *LazyPublicKeyBackend) ProvideKey(token *jwt.Token) (interface{}, error) {
	err := instance.loadIfRequired()
	if err != nil {
		return nil, err
	}
	if err := AssertPublicKeyAndTokenCombination(instance.publicKey, token); err != nil {
		return nil, err
	}
	return instance.publicKey, nil
}

func (instance *LazyPublicKeyBackend) loadIfRequired() error {
	finfo, err := os.Stat(instance.filename)
	if os.IsNotExist(err) {
		return fmt.Errorf("public key file '%s' does not exist", instance.filename)
	}
	if instance.publicKey == nil || !finfo.ModTime().Equal(instance.modTime) {
		instance.publicKey, err = ReadPublicKeyFile(instance.filename)
		if err != nil {
			return fmt.Errorf("could not load public key file '%s': %v", instance.filename, err)
		}
		if instance.publicKey == nil {
			return fmt.Errorf("no public key contained in file '%s'", instance.filename)
		}
	}
	return nil
}

// LazyHmacKeyBackend contains state to manage lazy key loading for HS family algorithms
type LazyHmacKeyBackend struct {
	filename string
	modTime  time.Time
	secret   []byte
}

// NewLazyHmacKeyBackend creates a new LazyHmacKeyBackend
func NewLazyHmacKeyBackend(value string) (*LazyHmacKeyBackend, error) {
	if len(value) <= 0 {
		return nil, fmt.Errorf("empty filename for secret provided")
	}
	return &LazyHmacKeyBackend{
		filename: value,
	}, nil
}

// ProvideKey will lazily load a secret key in a file, using a cached value if the key
// material has not changed.  An error is returned if the token does not match the
// expected signing algorithm.
func (instance *LazyHmacKeyBackend) ProvideKey(token *jwt.Token) (interface{}, error) {
	err := instance.loadIfRequired()
	if err != nil {
		return nil, err
	}
	if err := AssertHmacToken(token); err != nil {
		return nil, err
	}
	return instance.secret, nil
}

func (instance *LazyHmacKeyBackend) loadIfRequired() error {
	finfo, err := os.Stat(instance.filename)
	if os.IsNotExist(err) {
		return fmt.Errorf("public key file '%s' does not exist", instance.filename)
	}
	if instance.secret == nil || !finfo.ModTime().Equal(instance.modTime) {
		instance.secret, err = ioutil.ReadFile(instance.filename)
		if err != nil {
			return fmt.Errorf("could not load secret file '%s': %v", instance.filename, err)
		}
		if instance.secret == nil {
			return fmt.Errorf("no secret contained in file '%s'", instance.filename)
		}
	}
	return nil
}

// NewDefaultKeyBackends will read from the environment and return key backends based on
// values from environment variables JWT_SECRET or JWT_PUBLIC_KEY.  An error is returned if
// the keys are not able to be parsed or if an inconsistent configuration is found.
func NewDefaultKeyBackends() ([]KeyBackend, error) {
	result := []KeyBackend{}

	secret := os.Getenv(ENV_SECRET)
	if len(secret) > 0 {
		result = append(result, &HmacKeyBackend{
			secret: []byte(secret),
		})
	}

	envPubKey := os.Getenv(ENV_PUBLIC_KEY)
	if len(envPubKey) > 0 {
		pub, err := ParsePublicKey([]byte(envPubKey))
		if err != nil {
			return nil, fmt.Errorf("public key provided in environment variable %s could not be read: %v", ENV_PUBLIC_KEY, err)
		}
		result = append(result, &PublicKeyBackend{
			publicKey: pub,
		})
	}

	if len(result) == 0 {
		return nil, nil
	}
	if len(result) > 1 {
		return nil, fmt.Errorf("cannot configure both HMAC and RSA/ECDSA tokens on the same site")
	}

	return result, nil
}

// PublicKeyBackend is an RSA or ECDSA key provider
type PublicKeyBackend struct {
	publicKey interface{}
}

// ProvideKey will asssert that the token signing algorithm and the configured key match
func (instance *PublicKeyBackend) ProvideKey(token *jwt.Token) (interface{}, error) {
	if err := AssertPublicKeyAndTokenCombination(instance.publicKey, token); err != nil {
		return nil, err
	}
	return instance.publicKey, nil
}

// HmacKeyBacked is an HMAC-SHA key provider
type HmacKeyBackend struct {
	secret []byte
}

// ProvideKey will assert that the token signing algorithm and the configured key match
func (instance *HmacKeyBackend) ProvideKey(token *jwt.Token) (interface{}, error) {
	if err := AssertHmacToken(token); err != nil {
		return nil, err
	}
	return instance.secret, nil
}

// NoopKeyBackend always returns an error when no key signing method is specified
type NoopKeyBackend struct{}

// ProvideKey always returns an error when no key signing method is specified
func (instance *NoopKeyBackend) ProvideKey(token *jwt.Token) (interface{}, error) {
	return nil, fmt.Errorf("there is no keybackend available")
}
