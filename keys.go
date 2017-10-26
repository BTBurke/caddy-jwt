package jwt

import (
	"github.com/dgrijalva/jwt-go"
	"fmt"
	"time"
	"os"
	"io/ioutil"
)

const ENV_PUBLIC_KEY = "JWT_PUBLIC_KEY"
const ENV_SECRET = "JWT_SECRET"

type KeyBackend interface {
	ProvideKey(token *jwt.Token) (interface{}, error)
}

type LazyPublicKeyBackend struct {
	filename  string
	modTime   time.Time
	publicKey interface{}
}

func NewLazyPublicKeyFileBackend(value string) (*LazyPublicKeyBackend, error) {
	if len(value) <= 0 {
		return nil, fmt.Errorf("empty failename for public key provided")
	}
	return &LazyPublicKeyBackend{
		filename: value,
	}, nil
}

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

type LazyHmacKeyBackend struct {
	filename string
	modTime  time.Time
	secret   []byte
}

func NewLazyHmacKeyBackend(value string) (*LazyHmacKeyBackend, error) {
	if len(value) <= 0 {
		return nil, fmt.Errorf("empty failename for secret provided")
	}
	return &LazyHmacKeyBackend{
		filename: value,
	}, nil
}

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

func NewDefaultKeyBackends() ([]KeyBackend, error) {
	result := []KeyBackend{}

	secret := os.Getenv(ENV_SECRET)
	if len(secret) > 0 {
		result = append(result, &HmacKeyBackend{
			secret: []byte(secret),
		})
	}

	filename := os.Getenv(ENV_PUBLIC_KEY)
	if len(filename) > 0 {
		pub, err := ReadPublicKey([]byte(filename))
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
	return result, nil
}

type PublicKeyBackend struct {
	publicKey interface{}
}

func (instance *PublicKeyBackend) ProvideKey(token *jwt.Token) (interface{}, error) {
	if err := AssertPublicKeyAndTokenCombination(instance.publicKey, token); err != nil {
		return nil, err
	}
	return instance.publicKey, nil
}

type HmacKeyBackend struct {
	secret []byte
}

func (instance *HmacKeyBackend) ProvideKey(token *jwt.Token) (interface{}, error) {
	if err := AssertHmacToken(token); err != nil {
		return nil, err
	}
	return instance.secret, nil
}

type NoopKeyBackend struct {}

func (instance *NoopKeyBackend) ProvideKey(token *jwt.Token) (interface{}, error) {
	return nil, fmt.Errorf("there is no keybackend available")
}
