package jwt

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"io/ioutil"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/caddyserver/caddy/caddyhttp/httpserver"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

const (
	validToken     = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"
	malformedToken = "loremIpsum"
	rsaPublicKey   = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCx8HkixKMKDI43bBcL5TxhNsTy
4qbZW+LMzSazcFmICITg/c3BbDyCS88VO6hqPhfLzQsNbaZeKKqxQfVudhYQI2cX
9ID2IuYxw3M8vazffhiJjgKVXnNaGdUCnKVFKVPxklwVztxVE8tYmfN0cvAeNafc
KPMSbZEZEqQeFfkafQIDAQAB
-----END PUBLIC KEY-----
`
	rsaPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQCx8HkixKMKDI43bBcL5TxhNsTy4qbZW+LMzSazcFmICITg/c3B
bDyCS88VO6hqPhfLzQsNbaZeKKqxQfVudhYQI2cX9ID2IuYxw3M8vazffhiJjgKV
XnNaGdUCnKVFKVPxklwVztxVE8tYmfN0cvAeNafcKPMSbZEZEqQeFfkafQIDAQAB
AoGBAI1NRDTK6BnTzJ/QUyDcIi2ku5ORTyPuZtVx2FjIUCDJexPcGKeP1yE1KDZZ
UK1Fr8nkgvFf8Kx3KM1obokQdwV3QXTtENIaLoq3OTzmDihGmvrSqCvfWPQNF/Wn
qxcMedY3z/u4RqHW5Gects0K6RDWNua8QV0W6jazRFzcfcKhAkEA6tSQiOmjUUQz
+IKNr0BU+r127uNuly9t5w6Umqd4i9eYzRZRaNeokFCn7qOr/D70hMJynHLYr3sZ
KtBQUsFf5QJBAMH6+THDtPfFiB8Qtz67ucQq2DwWWUjCVFLd3rqMiRqZ7mJNEv+C
YOusKbw54UHCD5bgORYC5HXVg2hzBYj2trkCQCA/oLmsnCkE3L4774kppIHqkvKr
ePx6HvWkIvQ6G2vY57sCXZuwQg3PhcBX6b5yRtIUgfjKLMeseABRKzayJ6ECQQCe
KcCdrvETRWBj1AFViUNCi5ycAazzAmA24OkGOihgJDqWtDlVVD0qa8nry1W7hDup
zVE+fUVCPsFSnNZagq8hAkEA4tOFUKxqEDg+QXaJbFXiUTj9BMDUlEGTqGS/becS
99L5HGoSkzGQazoqD6bA6ZQwF+gUN1LweweK7LLcnZsVFg==
-----END RSA PRIVATE KEY-----
`
	ecdsaPublicKey = `-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBa7NUN5FTTN0snJpIxpljP3vZ/gQA
X7yBZpGBdHxPAKcV1dkxUPZeaqJKS5UsGL+Z5QzaaionFVddNNTiZxFZVmoAJxcF
lW5lqXQXg4iJ6yNd7dVrNDSvH6CyVNME9lhu4sDXsYEofjidtnNsSQ4cLIiW3q2J
6pF7NtHApTtl/GKDPoY=
-----END PUBLIC KEY-----
`
	ecdsaPrivateKey = `-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIB1QVyei7HRoi+sTQUj5RrvRiqZ5/xUSzqCm5hm/Xco5B/i2gZID/B
J48fw0IFpKcWX4DY8to2wQWI6vYH0Up+ekWgBwYFK4EEACOhgYkDgYYABAFrs1Q3
kVNM3SycmkjGmWM/e9n+BABfvIFmkYF0fE8ApxXV2TFQ9l5qokpLlSwYv5nlDNpq
KicVV1001OJnEVlWagAnFwWVbmWpdBeDiInrI13t1Ws0NK8foLJU0wT2WG7iwNex
gSh+OJ22c2xJDhwsiJberYnqkXs20cClO2X8YoM+hg==
-----END EC PRIVATE KEY-----
`
)

func TestCaddyJwt(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "CaddyJWT Suite")
}

func passThruHandler(w http.ResponseWriter, r *http.Request) (int, error) {
	// copy received headers back into response so they can be inspected
	for head, val := range r.Header {
		w.Header().Add(head, val[0])
	}
	return http.StatusOK, nil
}

func genToken(secret string, claims map[string]interface{}) string {
	token := jwt.New(jwt.SigningMethodHS256)
	token.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 1).Unix()

	for claim, value := range claims {
		token.Claims.(jwt.MapClaims)[claim] = value
	}
	validToken, err := token.SignedString([]byte(secret))
	if err != nil {
		Fail(fmt.Sprintf("unexpected error constructing token: %s", err))
	}
	return validToken
}

func genRSAToken(privatekey string, claims map[string]interface{}) string {
	token := jwt.New(jwt.SigningMethodRS256)
	token.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 1).Unix()

	for claim, value := range claims {
		token.Claims.(jwt.MapClaims)[claim] = value
	}
	pemKey, _ := jwt.ParseRSAPrivateKeyFromPEM([]byte(privatekey))

	validToken, err := token.SignedString(pemKey)
	if err != nil {
		Fail("failed constructing RSA token")
	}
	return validToken
}

func setSecretAndGetEnv(value string) *HmacKeyBackend {
	backend := setSecretAndTryGetEnv(value)
	if backend == nil {
		Fail("unexpected error constructing backends")
	}
	return backend
}

func setSecretAndTryGetEnv(value string) *HmacKeyBackend {
	if err := os.Setenv(ENV_SECRET, value); err != nil {
		Fail("unexpected error setting JWT_SECRET")
	}
	os.Unsetenv(ENV_PUBLIC_KEY)
	backends, err := NewDefaultKeyBackends()
	if err != nil {
		Fail(fmt.Sprintf("unexpected error constructing backends: %s", err))
	}
	if len(backends) != 1 {
		return nil
	}
	return backends[0].(*HmacKeyBackend)
}

func setPublicKeyAndGetEnv(value string) *PublicKeyBackend {
	backend := setPublicKeyAndTryGetEnv(value)
	if backend == nil {
		Fail("unexpected error constructing backends")
	}
	return backend
}

func setPublicKeyAndTryGetEnv(value string) *PublicKeyBackend {
	if err := os.Setenv(ENV_PUBLIC_KEY, value); err != nil {
		Fail("unexpected error setting JWT_PUBLIC_KEY")
	}
	os.Unsetenv(ENV_SECRET)
	backends, err := NewDefaultKeyBackends()
	if err != nil {
		Fail(fmt.Sprintf("unexpected error constructing backends: %s", err))
	}
	if len(backends) != 1 {
		return nil
	}
	return backends[0].(*PublicKeyBackend)
}

var _ = Describe("Auth", func() {
	AfterEach(func() {
		os.Unsetenv(ENV_PUBLIC_KEY)
		os.Unsetenv(ENV_SECRET)
	})
	Describe("Use environment to get secrets", func() {

		It("should get the JWT secret from the environment JWT_SECRET", func() {
			backend := setSecretAndGetEnv("secret")
			Expect(backend.secret).To(Equal([]byte("secret")))
		})

		It("should return an error JWT_SECRET not set", func() {
			backend := setSecretAndTryGetEnv("")
			Expect(backend).To(BeNil())
		})

		It("should find RSA key material stored on disk", func() {
			pemKey, _ := jwt.ParseRSAPublicKeyFromPEM([]byte(rsaPublicKey))
			keyfile, err := ioutil.TempFile(os.TempDir(), "testkey")
			if err != nil {
				Fail("Unexpected error creating temporary key file")
			}
			defer os.Remove(keyfile.Name())
			if _, err := keyfile.Write([]byte(rsaPublicKey)); err != nil {
				Fail("Unexpected error writing temporary key file")
			}
			if err := keyfile.Close(); err != nil {
				Fail("Unexpected error closing temporary key file")
			}
			backend, err := NewLazyPublicKeyFileBackend(keyfile.Name())
			if err != nil {
				Fail(err.Error())
			}
			if err := backend.loadIfRequired(); err != nil {
				Fail(err.Error())
			}
			Expect(backend.publicKey).To(Equal(pemKey))
			Expect(backend.filename).To(Equal(keyfile.Name()))
		})

		It("should find ECDSA key material stored on disk", func() {
			pemKey, _ := jwt.ParseECPublicKeyFromPEM([]byte(ecdsaPublicKey))
			keyfile, err := ioutil.TempFile(os.TempDir(), "testkey")
			if err != nil {
				Fail("Unexpected error creating temporary key file")
			}
			defer os.Remove(keyfile.Name())
			if _, err := keyfile.Write([]byte(ecdsaPublicKey)); err != nil {
				Fail("Unexpected error writing temporary key file")
			}
			if err := keyfile.Close(); err != nil {
				Fail("Unexpected error closing temporary key file")
			}
			backend, err := NewLazyPublicKeyFileBackend(keyfile.Name())
			if err != nil {
				Fail(err.Error())
			}
			if err := backend.loadIfRequired(); err != nil {
				Fail(err.Error())
			}
			Expect(backend.publicKey).To(Equal(pemKey))
			Expect(backend.filename).To(Equal(keyfile.Name()))
		})

		It("should find HMAC key material stored on disk and invalidate cache if file changes", func() {
			secret1 := []byte("secret1")
			secret2 := []byte("secret2")

			keyfile, err := ioutil.TempFile(os.TempDir(), "testkey")
			if err != nil {
				Fail("Unexpected error creating temporary key file")
			}
			defer os.Remove(keyfile.Name())

			if _, err := keyfile.Write(secret1); err != nil {
				Fail("Unexpected error writing temporary key file")
			}
			if err := keyfile.Close(); err != nil {
				Fail("Unexpected error closing temporary key file")
			}

			backend, err := NewLazyHmacKeyBackend(keyfile.Name())
			if err != nil {
				Fail(err.Error())
			}
			if err := backend.loadIfRequired(); err != nil {
				Fail(err.Error())
			}
			Expect(backend.secret).To(Equal(secret1))
			Expect(backend.filename).To(Equal(keyfile.Name()))

			// write new value and invalidate cache after short timeout to allow modinfo time to change
			time.Sleep(20 * time.Millisecond)
			if err := ioutil.WriteFile(keyfile.Name(), secret2, os.ModePerm); err != nil {
				Fail("Unexpected error overwriting keyfile in cache invalidation test")
			}

			if err := backend.loadIfRequired(); err != nil {
				Fail(err.Error())
			}
			Expect(backend.secret).To(Equal(secret2))
			Expect(backend.filename).To(Equal(keyfile.Name()))
		})

		It("should detect invalid configurations of auth backends", func() {
			os.Unsetenv("JWT_PUBLIC_KEY")
			os.Unsetenv("JWT_SECRET")
			backends, err := NewDefaultKeyBackends()
			if err != nil {
				Fail(err.Error())
			}
			Expect(len(backends)).To(Equal(0))
		})
	})

	Describe("Validate flatten map function", func() {

		listMap := map[string]interface{}{"context": map[string]interface{}{"user": map[string]interface{}{"roles": []string{"admin", "user"}}}}
		myMap := map[string]interface{}{"context": map[string]interface{}{"user": map[string]interface{}{"username": "foobar"}}}

		It("Should flatten map with dots", func() {
			result, err := Flatten(myMap, "", DotStyle)
			if err != nil {
				panic(err)
			}
			expectedMap := map[string]interface{}{"context.user.username": "foobar"}
			Expect(result).To(Equal(expectedMap))
		})
		It("Should flatten map and leave slices as is", func() {
			result, err := Flatten(listMap, "", DotStyle)
			if err != nil {
				panic(err)
			}
			expectedMap := map[string]interface{}{"context.user.roles": []string{"admin", "user"}}
			Expect(result).To(Equal(expectedMap))
		})
	})

	Describe("Find tokens in the request with a default token source config", func() {
		// Empty list should trigger the use of the default config.
		// This also tests each token source type individually.
		emptyTssList := []TokenSource{}
		It("should return the token if set in the Auhorization header", func() {
			req, _ := http.NewRequest("GET", "/testing", nil)
			req.Header.Set("Authorization", strings.Join([]string{"Bearer", validToken}, " "))
			token, err := ExtractToken(emptyTssList, req)
			Expect(err).To(BeNil())
			Expect(token).To(Equal(validToken))
		})

		It("should return the token if set in a cookie", func() {
			req, _ := http.NewRequest("GET", "/testing", nil)
			req.AddCookie(&http.Cookie{Name: "jwt_token", Value: validToken})
			token, err := ExtractToken(emptyTssList, req)
			Expect(err).To(BeNil())
			Expect(token).To(Equal(validToken))
		})

		It("should return the token if set as query parameter", func() {
			url := strings.Join([]string{"/testing?token=", validToken}, "")
			req, _ := http.NewRequest("GET", url, nil)
			token, err := ExtractToken(emptyTssList, req)
			Expect(err).To(BeNil())
			Expect(token).To(Equal(validToken))
		})
	})

	Describe("Find tokens in the request with a custom token source config", func() {
		It("should return the token from the first source that finds it in the request", func() {
			config := []TokenSource{
				&QueryTokenSource{
					ParamName: "custom_param",
				},
				&CookieTokenSource{
					CookieName: "custom_jwt_token",
				},
				&HeaderTokenSource{
					HeaderName: "Bearer",
				},
			}
			// These should be ignored as their names don't match.
			url := strings.Join([]string{"/testing?token=", malformedToken}, "")
			req, _ := http.NewRequest("GET", url, nil)
			req.AddCookie(&http.Cookie{Name: "jwt_token", Value: malformedToken})
			// This should be ignored as it is the last in the config list.
			req.Header.Set("Authorization", strings.Join([]string{"Bearer", malformedToken}, " "))
			// This should be extracted.
			req.AddCookie(&http.Cookie{Name: "custom_jwt_token", Value: validToken})
			token, err := ExtractToken(config, req)
			Expect(err).To(BeNil())
			Expect(token).To(Equal(validToken))
		})
	})

	Describe("Validate tokens in accordance with the JWT standard", func() {

		It("should validate a correctly formed token", func() {
			backend := setSecretAndGetEnv("secret")
			token := jwt.New(jwt.SigningMethodHS256)
			token.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 1).Unix()
			sToken, err := token.SignedString([]byte("secret"))
			if err != nil {
				Fail(fmt.Sprintf("unexpected error constructing token: %s", err))
			}
			vToken, err := ValidateToken(sToken, backend)

			Expect(err).To(BeNil())
			Expect(vToken.Valid).To(Equal(true))
		})

		It("should validate a correctly formed RSA token", func() {
			backend := setPublicKeyAndGetEnv(rsaPublicKey)
			token := jwt.New(jwt.SigningMethodRS256)
			token.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 1).Unix()

			secret, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(rsaPrivateKey))
			if err != nil {
				Fail(fmt.Sprintf("unexpected error constructing private key: %s", err))
			}
			sToken, err := token.SignedString(secret)
			if err != nil {
				Fail(fmt.Sprintf("unexpected error constructing token: %s", err))
			}

			vToken, err := ValidateToken(sToken, backend)

			Expect(err).To(BeNil())
			Expect(vToken.Valid).To(Equal(true))
		})

		It("should validate a correctly formed ECDSA token", func() {
			backend := setPublicKeyAndGetEnv(ecdsaPublicKey)
			token := jwt.New(jwt.SigningMethodES512)
			token.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 1).Unix()

			secret, err := jwt.ParseECPrivateKeyFromPEM([]byte(ecdsaPrivateKey))
			if err != nil {
				Fail(fmt.Sprintf("unexpected error constructing private key: %s", err))
			}
			sToken, err := token.SignedString(secret)
			if err != nil {
				Fail(fmt.Sprintf("unexpected error constructing token: %s", err))
			}

			vToken, err := ValidateToken(sToken, backend)

			Expect(err).To(BeNil())
			Expect(vToken.Valid).To(Equal(true))
		})

		It("should not validate a incorrectly formed token", func() {
			backend := setSecretAndGetEnv("secret")
			token := jwt.New(jwt.SigningMethodHS256)
			token.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 1).Unix()
			sToken, err := token.SignedString([]byte("notsecret"))
			if err != nil {
				Fail(fmt.Sprintf("unexpected error constructing token: %s", err))
			}

			vToken, err := ValidateToken(sToken, backend)

			Expect(err).To(HaveOccurred())
			Expect(vToken).To(BeNil())
		})

		It("should not validate a malformed token", func() {
			backend := setSecretAndGetEnv("secret")

			vToken, err := ValidateToken(malformedToken, backend)

			Expect(err).To(HaveOccurred())
			Expect(vToken).To(BeNil())
		})

		It("should not validate a token with an expired timestamp", func() {
			backend := setSecretAndGetEnv("secret")
			token := jwt.New(jwt.SigningMethodHS256)
			token.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * -1).Unix()
			sToken, err := token.SignedString([]byte("secret"))
			if err != nil {
				Fail(fmt.Sprintf("unexpected error constructing token: %s", err))
			}

			vToken, err := ValidateToken(sToken, backend)

			Expect(err).To(HaveOccurred())
			Expect(vToken).To(BeNil())
		})

		It("should not allow JWT with algorithm none", func() {
			backend := setSecretAndGetEnv("secret")
			token := jwt.New(jwt.SigningMethodHS256)
			token.Header["alg"] = "none"
			token.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 1).Unix()
			sToken, err := token.SignedString([]byte("secret"))
			if err != nil {
				Fail(fmt.Sprintf("unexpected error constructing token: %s", err))
			}

			vToken, err := ValidateToken(sToken, backend)

			Expect(err).To(HaveOccurred())
			Expect(vToken).To(BeNil())
		})
	})
	Describe("Redirect on access deny works", func() {
		It("return 303 when a redirect is configured and access denied", func() {
			req, err := http.NewRequest("GET", "/testing", nil)

			rec := httptest.NewRecorder()
			rw := Auth{
				Rules: []Rule{{Path: "/testing", Redirect: "/login"}},
			}
			result, err := rw.ServeHTTP(rec, req)
			if err != nil {
				Fail(fmt.Sprintf("unexpected error constructing server: %s", err))
			}

			Expect(result).To(Equal(http.StatusSeeOther))
			Expect(rec.Result().StatusCode).To(Equal(http.StatusSeeOther))
			Expect(rec.Result().Header.Get("Location")).To(Equal("/login"))
		})
		It("variables in location value are replaced", func() {
			req, err := http.NewRequest("GET", "/testing", nil)

			rec := httptest.NewRecorder()
			rw := Auth{
				Rules: []Rule{{Path: "/testing", Redirect: "/login?backTo={rewrite_uri}"}},
			}
			result, err := rw.ServeHTTP(rec, req)
			if err != nil {
				Fail(fmt.Sprintf("unexpected error constructing server: %s", err))
			}

			Expect(result).To(Equal(http.StatusSeeOther))
			Expect(rec.Result().StatusCode).To(Equal(http.StatusSeeOther))
			Expect(rec.Result().Header.Get("Location")).To(Equal("/login?backTo=/testing"))
		})
	})
	Describe("Function correctly as an authorization middleware for malformed paths", func() {
		It("return 401 when no authorization header and the path is protected (malformed path - 1st level)", func() {
			rw := Auth{
				Next: httpserver.HandlerFunc(passThruHandler),
				Rules: []Rule{
					Rule{Path: "/"},
				},
				Realm: "testing.com",
			}
			req, err := http.NewRequest("GET", "//testing", nil)

			rec := httptest.NewRecorder()
			result, err := rw.ServeHTTP(rec, req)
			if err != nil {
				Fail(fmt.Sprintf("unexpected error constructing server: %s", err))
			}

			Expect(result).To(Equal(http.StatusUnauthorized))
			Expect(rec.Result().Header.Get("WWW-Authenticate")).To(Equal("Bearer realm=\"testing.com\",error=\"invalid_token\""))
		})
		It("return 401 when no authorization header and the path is protected (malformed path - root level)", func() {
			rw := Auth{
				Next: httpserver.HandlerFunc(passThruHandler),
				Rules: []Rule{
					Rule{Path: "/"},
				},
				Realm: "testing.com",
			}
			req, err := http.NewRequest("GET", "//", nil)

			rec := httptest.NewRecorder()
			result, err := rw.ServeHTTP(rec, req)
			if err != nil {
				Fail(fmt.Sprintf("unexpected error constructing server: %s", err))
			}

			Expect(result).To(Equal(http.StatusUnauthorized))
			Expect(rec.Result().Header.Get("WWW-Authenticate")).To(Equal("Bearer realm=\"testing.com\",error=\"invalid_token\""))
		})

		It("return 401 when no authorization header and the path is protected (malformed path - 2nd level)", func() {
			rw := Auth{
				Next: httpserver.HandlerFunc(passThruHandler),
				Rules: []Rule{
					Rule{Path: "/testing/test"},
				},
				Realm: "testing.com",
			}
			req, err := http.NewRequest("GET", "/testing//test", nil)

			rec := httptest.NewRecorder()
			result, err := rw.ServeHTTP(rec, req)
			if err != nil {
				Fail(fmt.Sprintf("unexpected error constructing server: %s", err))
			}

			Expect(result).To(Equal(http.StatusUnauthorized))
			Expect(rec.Result().Header.Get("WWW-Authenticate")).To(Equal("Bearer realm=\"testing.com\",error=\"invalid_token\""))
		})

		It("return 401 when no authorization header and the path is protected (malformed path - 2nd of nested)", func() {
			rw := Auth{
				Next: httpserver.HandlerFunc(passThruHandler),
				Rules: []Rule{
					Rule{Path: "/testing/test/secret"},
				},
				Realm: "testing.com",
			}
			req, err := http.NewRequest("GET", "/testing//test/secret", nil)

			rec := httptest.NewRecorder()
			result, err := rw.ServeHTTP(rec, req)
			if err != nil {
				Fail(fmt.Sprintf("unexpected error constructing server: %s", err))
			}

			Expect(result).To(Equal(http.StatusUnauthorized))
			Expect(rec.Result().Header.Get("WWW-Authenticate")).To(Equal("Bearer realm=\"testing.com\",error=\"invalid_token\""))
		})
		It("return 401 when no authorization header and the path is protected (malformed path - 3rd level)", func() {
			rw := Auth{
				Next: httpserver.HandlerFunc(passThruHandler),
				Rules: []Rule{
					Rule{Path: "/testing/test/secret"},
				},
				Realm: "testing.com",
			}
			req, err := http.NewRequest("GET", "/testing/test//secret", nil)

			rec := httptest.NewRecorder()
			result, err := rw.ServeHTTP(rec, req)
			if err != nil {
				Fail(fmt.Sprintf("unexpected error constructing server: %s", err))
			}

			Expect(result).To(Equal(http.StatusUnauthorized))
			Expect(rec.Result().Header.Get("WWW-Authenticate")).To(Equal("Bearer realm=\"testing.com\",error=\"invalid_token\""))
		})

	})
	Describe("Function correctly as an authorization middleware", func() {
		backend := setSecretAndGetEnv("secret")
		rw := Auth{
			Next: httpserver.HandlerFunc(passThruHandler),
			Rules: []Rule{
				Rule{Path: "/testing", ExceptedPaths: []string{"/testing/excepted"}, KeyBackends: []KeyBackend{backend}},
			},
			Realm: "testing.com",
		}
		token := jwt.New(jwt.SigningMethodHS256)
		token.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 1).Unix()
		token.Claims.(jwt.MapClaims)["user"] = "test"
		token.Claims.(jwt.MapClaims)["int32"] = int32(10)
		token.Claims.(jwt.MapClaims)["float32"] = float32(3.14159)
		token.Claims.(jwt.MapClaims)["float64"] = float64(3.14159)
		token.Claims.(jwt.MapClaims)["bool"] = true
		token.Claims.(jwt.MapClaims)["list"] = []string{"foo", "bar", "bazz"}
		token.Claims.(jwt.MapClaims)["http://test.com/path"] = "true"

		validToken, err := token.SignedString([]byte("secret"))
		if err != nil {
			Fail(fmt.Sprintf("unexpected error constructing token: %s", err))
		}

		invalidToken, err := token.SignedString([]byte("notsecret"))
		if err != nil {
			Fail(fmt.Sprintf("unexpected error constructing token: %s", err))
		}

		It("return 401 when no authorization header and the path is protected", func() {
			req, err := http.NewRequest("GET", "/testing", nil)

			rec := httptest.NewRecorder()
			result, err := rw.ServeHTTP(rec, req)
			if err != nil {
				Fail(fmt.Sprintf("unexpected error constructing server: %s", err))
			}

			Expect(result).To(Equal(http.StatusUnauthorized))
			Expect(rec.Result().Header.Get("WWW-Authenticate")).To(Equal("Bearer realm=\"testing.com\",error=\"invalid_token\""))
		})

		It("return 401 when no authorization header and the path is protected (malformed path)", func() {
			req, err := http.NewRequest("GET", "//testing", nil)

			rec := httptest.NewRecorder()
			result, err := rw.ServeHTTP(rec, req)
			if err != nil {
				Fail(fmt.Sprintf("unexpected error constructing server: %s", err))
			}

			Expect(result).To(Equal(http.StatusUnauthorized))
			Expect(rec.Result().Header.Get("WWW-Authenticate")).To(Equal("Bearer realm=\"testing.com\",error=\"invalid_token\""))
		})

		It("return 401 when no token and the path is protected", func() {
			req, err := http.NewRequest("GET", "/testing", nil)
			req.Header.Set("Authorization", strings.Join([]string{"Basic", "QWxhZGRpbjpvcGVuIHNlc2FtZQ=="}, " "))

			rec := httptest.NewRecorder()
			result, err := rw.ServeHTTP(rec, req)
			if err != nil {
				Fail(fmt.Sprintf("unexpected error constructing server: %s", err))
			}

			Expect(result).To(Equal(http.StatusUnauthorized))
			Expect(rec.Result().Header.Get("WWW-Authenticate")).To(Equal("Bearer realm=\"testing.com\",error=\"invalid_token\""))
		})

		It("return 401 when the token is not valid and the path is protected", func() {
			req, err := http.NewRequest("GET", "/testing", nil)
			req.Header.Set("Authorization", strings.Join([]string{"Bearer", invalidToken}, " "))

			rec := httptest.NewRecorder()
			result, err := rw.ServeHTTP(rec, req)
			if err != nil {
				Fail(fmt.Sprintf("unexpected error constructing server: %s", err))
			}

			Expect(result).To(Equal(http.StatusUnauthorized))
			Expect(rec.Result().Header.Get("WWW-Authenticate")).To(Equal("Bearer realm=\"testing.com\",error=\"invalid_token\""))
		})

		It("allow valid requests to continue to next handler", func() {
			req, err := http.NewRequest("GET", "/testing", nil)
			req.Header.Set("Authorization", strings.Join([]string{"Bearer", validToken}, " "))

			rec := httptest.NewRecorder()
			result, err := rw.ServeHTTP(rec, req)
			if err != nil {
				Fail(fmt.Sprintf("unexpected error constructing server: %s", err))
			}

			Expect(result).To(Equal(http.StatusOK))
		})

		It("allow OPTIONS requests to continue to next handler", func() {
			req, err := http.NewRequest("OPTIONS", "/testing", nil)

			rec := httptest.NewRecorder()
			result, err := rw.ServeHTTP(rec, req)
			if err != nil {
				Fail(fmt.Sprintf("unexpected error constructing server: %s", err))
			}

			Expect(result).To(Equal(http.StatusOK))
		})

		It("allow unprotected requests to continue to next handler", func() {
			req, err := http.NewRequest("GET", "/unprotected", nil)

			rec := httptest.NewRecorder()
			result, err := rw.ServeHTTP(rec, req)
			if err != nil {
				Fail(fmt.Sprintf("unexpected error constructing server: %s", err))
			}

			Expect(result).To(Equal(http.StatusOK))
		})

		It("allow excepted path requests to continue to next handler", func() {
			req, err := http.NewRequest("GET", "/testing/excepted", nil)

			rec := httptest.NewRecorder()
			result, err := rw.ServeHTTP(rec, req)
			if err != nil {
				Fail(fmt.Sprintf("unexpected error constructing server: %s", err))
			}

			Expect(result).To(Equal(http.StatusOK))
		})

		It("set claims as individual headers", func() {
			req, err := http.NewRequest("GET", "/testing", nil)
			req.Header.Set("Authorization", strings.Join([]string{"Bearer", validToken}, " "))

			rec := httptest.NewRecorder()
			result, err := rw.ServeHTTP(rec, req)
			if err != nil {
				Fail(fmt.Sprintf("unexpected error constructing server: %s", err))
			}

			Expect(result).To(Equal(http.StatusOK))
			expectedHeaders := map[string]string{
				"Token-Claim-User":                       "test",
				"Token-Claim-Bool":                       "true",
				"Token-Claim-Float32":                    "3.14159",
				"Token-Claim-Float64":                    "3.14159",
				"Token-Claim-Int32":                      "10",
				"Token-Claim-List":                       "foo,bar,bazz",
				"Token-Claim-Http:%2F%2Ftest.com%2Fpath": "true",
			}
			returnedHeaders := rec.Header()
			for head, value := range expectedHeaders {
				val, ok := returnedHeaders[head]
				if !ok {
					Fail(fmt.Sprintf("expected header not in response: %v. Have: %v", head, returnedHeaders))
				}
				Expect(val[0]).To(Equal(value))
			}

		})
		Describe("Strip headers when set", func() {
			backend := setSecretAndGetEnv("secret")
			rw := Auth{
				Next: httpserver.HandlerFunc(passThruHandler),
				Rules: []Rule{
					Rule{Path: "/testing", ExceptedPaths: []string{"/testing/excepted"}, StripHeader: true, KeyBackends: []KeyBackend{backend}},
				},
				Realm: "testing.com",
			}
			token := jwt.New(jwt.SigningMethodHS256)
			token.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 1).Unix()
			token.Claims.(jwt.MapClaims)["user"] = "test"
			token.Claims.(jwt.MapClaims)["int32"] = int32(10)
			token.Claims.(jwt.MapClaims)["float32"] = float32(3.14159)
			token.Claims.(jwt.MapClaims)["float64"] = float64(3.14159)
			token.Claims.(jwt.MapClaims)["bool"] = true
			token.Claims.(jwt.MapClaims)["list"] = []string{"foo", "bar", "bazz"}
			token.Claims.(jwt.MapClaims)["http://test.com/path.me"] = "true"

			validToken, err := token.SignedString([]byte("secret"))
			if err != nil {
				Fail(fmt.Sprintf("unexpected error constructing token: %s", err))
			}

			It("set claims as individual headers, and strips if necessary", func() {
				req, err := http.NewRequest("GET", "/testing", nil)
				req.Header.Set("Authorization", strings.Join([]string{"Bearer", validToken}, " "))

				rec := httptest.NewRecorder()
				result, err := rw.ServeHTTP(rec, req)
				if err != nil {
					Fail(fmt.Sprintf("unexpected error constructing server: %s", err))
				}

				Expect(result).To(Equal(http.StatusOK))
				expectedHeaders := map[string]string{
					"Token-Claim-User":    "test",
					"Token-Claim-Bool":    "true",
					"Token-Claim-Float32": "3.14159",
					"Token-Claim-Float64": "3.14159",
					"Token-Claim-Int32":   "10",
					"Token-Claim-List":    "foo,bar,bazz",
					"Token-Claim-Path.me": "true",
				}
				returnedHeaders := rec.Header()
				for head, value := range expectedHeaders {
					val, ok := returnedHeaders[head]
					if !ok {
						Fail(fmt.Sprintf("expected header not in response: %v. Have: %v", head, returnedHeaders))
					}
					Expect(val[0]).To(Equal(value))
				}

			})
		})
		Describe("Function correctly as an authorization middleware for complex access rules", func() {
			backend := setSecretAndGetEnv("secret")
			tokenUser := genToken("secret", map[string]interface{}{"user": "test", "role": "member"})
			tokenNotUser := genToken("secret", map[string]interface{}{"user": "bad"})
			tokenAdmin := genToken("secret", map[string]interface{}{"role": "admin"})
			accessRuleAllowUser := AccessRule{Authorize: ALLOW,
				Claim: "user",
				Value: "test",
			}
			accessRuleAllowRole := AccessRule{Authorize: ALLOW,
				Claim: "role",
				Value: "admin",
			}
			accessRuleDenyRole := AccessRule{Authorize: DENY,
				Claim: "role",
				Value: "member",
			}
			ruleAllowUser := Rule{Path: "/testing", AccessRules: []AccessRule{accessRuleAllowUser}, KeyBackends: []KeyBackend{backend}}
			ruleDenyRole := Rule{Path: "/testing", AccessRules: []AccessRule{accessRuleDenyRole}, KeyBackends: []KeyBackend{backend}}
			ruleAllowRoleAllowUser := []Rule{Rule{Path: "/testing", AccessRules: []AccessRule{accessRuleAllowRole, accessRuleAllowUser}, KeyBackends: []KeyBackend{backend}}}
			ruleDenyRoleAllowUser := []Rule{Rule{Path: "/testing", AccessRules: []AccessRule{accessRuleDenyRole, accessRuleAllowUser}, KeyBackends: []KeyBackend{backend}}}

			It("should allow authorization based on a specific claim value", func() {
				rw := Auth{
					Next:  httpserver.HandlerFunc(passThruHandler),
					Rules: []Rule{ruleAllowUser},
				}

				req, err := http.NewRequest("GET", "/testing", nil)
				req.Header.Set("Authorization", strings.Join([]string{"Bearer", tokenUser}, " "))

				rec := httptest.NewRecorder()
				result, err := rw.ServeHTTP(rec, req)
				if err != nil {
					Fail(fmt.Sprintf("unexpected error constructing server: %s", err))
				}

				Expect(result).To(Equal(http.StatusOK))
			})
			It("should deny authorization based on a specific claim value that doesnt match", func() {
				rw := Auth{
					Next:  httpserver.HandlerFunc(passThruHandler),
					Rules: []Rule{ruleAllowUser},
					Realm: "testing.com",
				}

				req, err := http.NewRequest("GET", "/testing", nil)
				req.Header.Set("Authorization", strings.Join([]string{"Bearer", tokenNotUser}, " "))

				rec := httptest.NewRecorder()
				result, err := rw.ServeHTTP(rec, req)
				if err != nil {
					Fail(fmt.Sprintf("unexpected error constructing server: %s", err))
				}

				Expect(result).To(Equal(http.StatusForbidden))
				Expect(rec.Result().Header.Get("WWW-Authenticate")).To(Equal("Bearer realm=\"testing.com\",error=\"insufficient_scope\""))
			})
			It("should correctly apply rules in order with multiple ALLOWs", func() {
				// tests situation where user is denied based on wrong role
				// but subsequent allow based on username is ok
				rw := Auth{
					Next:  httpserver.HandlerFunc(passThruHandler),
					Rules: ruleAllowRoleAllowUser,
				}

				req, err := http.NewRequest("GET", "/testing", nil)
				req.Header.Set("Authorization", strings.Join([]string{"Bearer", tokenUser}, " "))

				rec := httptest.NewRecorder()
				result, err := rw.ServeHTTP(rec, req)
				if err != nil {
					Fail(fmt.Sprintf("unexpected error constructing server: %s", err))
				}

				Expect(result).To(Equal(http.StatusOK))
			})
			It("should correctly apply rules in order with a DENY then ALLOW", func() {
				// test situation where default deny for a particular role
				// subsequent rule based on user ok
				rw := Auth{
					Next:  httpserver.HandlerFunc(passThruHandler),
					Rules: ruleDenyRoleAllowUser,
				}

				req, err := http.NewRequest("GET", "/testing", nil)
				req.Header.Set("Authorization", strings.Join([]string{"Bearer", tokenUser}, " "))

				rec := httptest.NewRecorder()
				result, err := rw.ServeHTTP(rec, req)
				if err != nil {
					Fail(fmt.Sprintf("unexpected error constructing server: %s", err))
				}

				Expect(result).To(Equal(http.StatusOK))
			})

			It("should correctly deny based on specific match", func() {
				// tests situation where user is denied based on wrong role
				// but subsequent allow based on username is ok
				rw := Auth{
					Next:  httpserver.HandlerFunc(passThruHandler),
					Rules: []Rule{ruleDenyRole},
					Realm: "testing.com",
				}

				req, err := http.NewRequest("GET", "/testing", nil)
				req.Header.Set("Authorization", strings.Join([]string{"Bearer", tokenUser}, " "))

				rec := httptest.NewRecorder()
				result, err := rw.ServeHTTP(rec, req)
				if err != nil {
					Fail(fmt.Sprintf("unexpected error constructing server: %s", err))
				}

				Expect(result).To(Equal(http.StatusForbidden))
				Expect(rec.Result().Header.Get("WWW-Authenticate")).To(Equal("Bearer realm=\"testing.com\",error=\"insufficient_scope\""))
			})

			It("should allow based on no match to DENY", func() {
				// tests situation where user is denied based on wrong role
				// but subsequent allow based on username is ok
				rw := Auth{
					Next:  httpserver.HandlerFunc(passThruHandler),
					Rules: []Rule{ruleDenyRole},
				}

				req, err := http.NewRequest("GET", "/testing", nil)
				req.Header.Set("Authorization", strings.Join([]string{"Bearer", tokenAdmin}, " "))

				rec := httptest.NewRecorder()
				result, err := rw.ServeHTTP(rec, req)
				if err != nil {
					Fail(fmt.Sprintf("unexpected error constructing server: %s", err))
				}

				Expect(result).To(Equal(http.StatusOK))
			})
		})
		Describe("Function correctly as an authorization middleware for list types", func() {

			tokenGroups := genToken("secret", map[string]interface{}{"group": []string{"admin", "user"}})
			tokenGroupsOperator := genToken("secret", map[string]interface{}{"group": []string{"operator"}})
			ruleAllowUser := Rule{Path: "/testing", AccessRules: []AccessRule{
				AccessRule{Authorize: ALLOW,
					Claim: "group",
					Value: "admin",
				},
				AccessRule{Authorize: DENY,
					Claim: "group",
					Value: "operator",
				},
			}, KeyBackends: []KeyBackend{backend}}
			BeforeEach(func() {
				if err := os.Setenv("JWT_SECRET", "secret"); err != nil {
					Fail("Could not set environment secret")
				}
				if err := os.Setenv("JWT_PUBLIC_KEY", ""); err != nil {
					Fail("Could not unset secret")
				}
			})

			It("should allow claim values, which are part of a list", func() {
				rw := Auth{
					Next:  httpserver.HandlerFunc(passThruHandler),
					Rules: []Rule{ruleAllowUser},
				}

				req, err := http.NewRequest("GET", "/testing", nil)
				req.Header.Set("Authorization", strings.Join([]string{"Bearer", tokenGroups}, " "))

				rec := httptest.NewRecorder()
				result, err := rw.ServeHTTP(rec, req)
				if err != nil {
					Fail(fmt.Sprintf("unexpected error constructing server: %s", err))
				}

				Expect(result).To(Equal(http.StatusOK))
			})
			It("should deny claim values, which are part of a list", func() {
				rw := Auth{
					Next:  httpserver.HandlerFunc(passThruHandler),
					Rules: []Rule{ruleAllowUser},
					Realm: "testing.com",
				}

				req, err := http.NewRequest("GET", "/testing", nil)
				req.Header.Set("Authorization", strings.Join([]string{"Bearer", tokenGroupsOperator}, " "))

				rec := httptest.NewRecorder()
				result, err := rw.ServeHTTP(rec, req)
				if err != nil {
					Fail(fmt.Sprintf("unexpected error constructing server: %s", err))
				}

				Expect(result).To(Equal(http.StatusForbidden))
				Expect(rec.Result().Header.Get("WWW-Authenticate")).To(Equal("Bearer realm=\"testing.com\",error=\"insufficient_scope\""))
			})
		})

		Describe("Prevent spoofing of claims headers", func() {
			It("should remove spoofed claims with no JWT provided", func() {
				rw := Auth{
					Next:  httpserver.HandlerFunc(passThruHandler),
					Rules: []Rule{{Path: "/testing", Passthrough: true}},
				}
				req, err := http.NewRequest("GET", "/testing", nil)
				req.Header.Set("Token-Claim-Spoofed", "spoof")

				rec := httptest.NewRecorder()
				result, err := rw.ServeHTTP(rec, req)
				if err != nil {
					Fail(fmt.Sprintf("unexpected error constructing server: %s", err))
				}

				Expect(result).To(Equal(http.StatusOK))
				Expect(rec.Result().Header.Get("Token-Claim-Spoofed")).To(Equal(""))
			})

			It("should remove spoofed claims with valid token provided", func() {
				rw := Auth{
					Next:  httpserver.HandlerFunc(passThruHandler),
					Rules: []Rule{{Path: "/testing", Passthrough: true}},
				}
				req, err := http.NewRequest("GET", "/testing", nil)
				req.Header.Set("Token-Claim-Spoofed", "spoof")
				req.Header.Set("Authorization", strings.Join([]string{"Bearer", validToken}, " "))

				rec := httptest.NewRecorder()
				result, err := rw.ServeHTTP(rec, req)
				if err != nil {
					Fail(fmt.Sprintf("unexpected error constructing server: %s", err))
				}

				Expect(result).To(Equal(http.StatusOK))
				Expect(rec.Result().Header.Get("Token-Claim-Spoofed")).To(Equal(""))
			})

			It("should remove spoofed claims with invalid token provided", func() {
				rw := Auth{
					Next:  httpserver.HandlerFunc(passThruHandler),
					Rules: []Rule{{Path: "/testing", Passthrough: true}},
				}
				req, err := http.NewRequest("GET", "/testing", nil)
				req.Header.Set("Token-Claim-Spoofed", "spoof")
				req.Header.Set("Authorization", strings.Join([]string{"Bearer", "foo"}, " "))

				rec := httptest.NewRecorder()
				result, err := rw.ServeHTTP(rec, req)
				if err != nil {
					Fail(fmt.Sprintf("unexpected error constructing server: %s", err))
				}

				Expect(result).To(Equal(http.StatusOK))
				Expect(rec.Result().Header.Get("Token-Claim-Spoofed")).To(Equal(""))
			})
		})

		Describe("Handle multiple keyfiles correctly", func() {
			It("should allow access when one of the keyfiles matches", func() {
				key1, err := createKeyFile(rsaPublicKey)
				if err != nil {
					Fail(fmt.Sprintf("unexpected error creating key file: %s", err))
				}
				backend1, err := NewLazyPublicKeyFileBackend(key1)
				if err != nil {
					Fail(err.Error())
				}
				defer os.Remove(key1)
				key2, err := createKeyFile("notvalidkey")
				if err != nil {
					Fail(fmt.Sprintf("unexpected error creating key file: %s", err))
				}
				backend2, err := NewLazyPublicKeyFileBackend(key2)
				if err != nil {
					Fail(err.Error())
				}
				defer os.Remove(key2)

				token := genRSAToken(rsaPrivateKey, map[string]interface{}{"test": "test"})

				rw := Auth{
					Next:  httpserver.HandlerFunc(passThruHandler),
					Rules: []Rule{{Path: "/testing", KeyBackends: []KeyBackend{backend1, backend2}}},
				}
				req, err := http.NewRequest("GET", "/testing", nil)
				req.Header.Set("Authorization", strings.Join([]string{"Bearer", token}, " "))

				rec := httptest.NewRecorder()
				result, err := rw.ServeHTTP(rec, req)
				if err != nil {
					Fail(fmt.Sprintf("unexpected error constructing server: %s", err))
				}

				Expect(result).To(Equal(http.StatusOK))
			})
			It("should allow access when one of the keyfiles matches in any order", func() {
				key1, err := createKeyFile(rsaPublicKey)
				if err != nil {
					Fail(fmt.Sprintf("unexpected error creating key file: %s", err))
				}
				backend1, err := NewLazyPublicKeyFileBackend(key1)
				if err != nil {
					Fail(err.Error())
				}
				defer os.Remove(key1)
				key2, err := createKeyFile("notvalidkey")
				if err != nil {
					Fail(fmt.Sprintf("unexpected error creating key file: %s", err))
				}
				backend2, err := NewLazyPublicKeyFileBackend(key2)
				if err != nil {
					Fail(err.Error())
				}
				defer os.Remove(key2)

				token := genRSAToken(rsaPrivateKey, map[string]interface{}{"test": "test"})

				rw := Auth{
					Next:  httpserver.HandlerFunc(passThruHandler),
					Rules: []Rule{{Path: "/testing", KeyBackends: []KeyBackend{backend2, backend2, backend2, backend1}}},
				}
				req, err := http.NewRequest("GET", "/testing", nil)
				req.Header.Set("Authorization", strings.Join([]string{"Bearer", token}, " "))

				rec := httptest.NewRecorder()
				result, err := rw.ServeHTTP(rec, req)
				if err != nil {
					Fail(fmt.Sprintf("unexpected error constructing server: %s", err))
				}

				Expect(result).To(Equal(http.StatusOK))
			})
			It("should deny access when all keyfiles dont validate", func() {
				key2, err := createKeyFile("notvalidkey")
				if err != nil {
					Fail(fmt.Sprintf("unexpected error creating key file: %s", err))
				}
				backend2, err := NewLazyPublicKeyFileBackend(key2)
				if err != nil {
					Fail(err.Error())
				}
				defer os.Remove(key2)

				token := genRSAToken(rsaPrivateKey, map[string]interface{}{"test": "test"})

				rw := Auth{
					Next:  httpserver.HandlerFunc(passThruHandler),
					Rules: []Rule{{Path: "/testing", KeyBackends: []KeyBackend{backend2, backend2, backend2}}},
				}
				req, err := http.NewRequest("GET", "/testing", nil)
				req.Header.Set("Authorization", strings.Join([]string{"Bearer", token}, " "))

				rec := httptest.NewRecorder()
				result, err := rw.ServeHTTP(rec, req)
				if err != nil {
					Fail(fmt.Sprintf("unexpected error constructing server: %s", err))
				}

				Expect(result).To(Equal(http.StatusUnauthorized))
			})
		})
	})

})

func createKeyFile(key string) (string, error) {
	f, err := ioutil.TempFile("", "jwt")
	if err != nil {
		return "", err
	}
	if _, err := f.Write([]byte(key)); err != nil {
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	return f.Name(), nil
}
