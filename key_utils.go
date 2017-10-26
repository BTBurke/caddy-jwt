package jwt

import (
	"github.com/dgrijalva/jwt-go"
	"io/ioutil"
	"crypto/rsa"
	"crypto/ecdsa"
	"fmt"
)

func ReadPublicKey(pem []byte) (interface{}, error) {
	result, err := jwt.ParseRSAPublicKeyFromPEM(pem)
	if err != nil {
		result2, err2 := jwt.ParseECPublicKeyFromPEM(pem)
		if err2 == nil {
			return result2, nil
		}
	}
	return result, err
}

func ReadPublicKeyFile(filepath string) (interface{}, error) {
	content, err := ioutil.ReadFile(filepath)
	if err != nil {
		return nil, err
	}
	return ReadPublicKey(content)
}

func IsRsaPublicKey(key interface{}) bool {
	_, ok := key.(*rsa.PublicKey)
	return ok
}

func IsEcdsaPublicKey(key interface{}) bool {
	_, ok := key.(*ecdsa.PublicKey)
	return ok
}

func IsRsaToken(token *jwt.Token) bool {
	_, ok := token.Method.(*jwt.SigningMethodRSA)
	return ok
}

func IsEcdsaToken(token *jwt.Token) bool {
	_, ok := token.Method.(*jwt.SigningMethodECDSA)
	return ok
}

func IsHmacToken(token *jwt.Token) bool {
	_, ok := token.Method.(*jwt.SigningMethodHMAC)
	return ok
}

func AssertPublicKeyAndTokenCombination(publicKey interface{}, token *jwt.Token) error {
	if IsRsaPublicKey(publicKey) && !IsRsaToken(token) {
		return fmt.Errorf("expect token signed with RSA but got %v", token.Header["alg"])
	}
	if IsEcdsaPublicKey(publicKey) && !IsEcdsaToken(token) {
		return fmt.Errorf("expect token signed with ECDSA but got %v", token.Header["alg"])
	}
	return nil
}

func AssertHmacToken(token *jwt.Token) error {
	if !IsHmacToken(token) {
		return fmt.Errorf("expect token signed with HMAC but got %v", token.Header["alg"])
	}
	return nil
}
