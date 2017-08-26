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

	"github.com/dgrijalva/jwt-go"
	"github.com/mholt/caddy/caddyhttp/httpserver"
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

var _ = Describe("Auth", func() {

	Describe("Use environment to get secrets", func() {

		It("should get the JWT secret from the environment JWT_SECRET", func() {
			if err := os.Setenv("JWT_SECRET", "secret"); err != nil {
				Fail("Unexpected error setting JWT_SECRET")
			}
			b := backend{}
			secret := b.GetHMACSecret()
			Expect(secret).To(Equal([]byte("secret")))
		})

		It("should return an error JWT_SECRET not set", func() {
			if err := os.Setenv("JWT_SECRET", ""); err != nil {
				Fail("Unexpected error setting JWT_SECRET")
			}
			b := backend{}
			secret := b.GetHMACSecret()
			Expect(secret).To(BeNil())
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

			b := backend{
				current: keycache{
					KeyFile:     keyfile.Name(),
					KeyFileType: RSA,
				},
				cache: make(map[string]keycache),
			}
			rsakey := b.GetRSAPublicKey()
			Expect(rsakey).To(Equal(pemKey))
			Expect(b.cache[keyfile.Name()].Key).To(Equal([]byte(rsaPublicKey)))
			Expect(b.current.KeyFile).To(Equal(keyfile.Name()))

			rsakeyCached := b.GetRSAPublicKey()
			Expect(rsakeyCached).To(Equal(pemKey))
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

			b := backend{
				current: keycache{
					KeyFile:     keyfile.Name(),
					KeyFileType: HMAC,
				},
				cache: make(map[string]keycache),
			}
			key1 := b.GetHMACSecret()
			Expect(key1).To(Equal(secret1))
			Expect(b.cache[keyfile.Name()].Key).To(Equal(secret1))
			Expect(b.current.KeyFile).To(Equal(keyfile.Name()))

			key1Cached := b.GetHMACSecret()
			Expect(key1Cached).To(Equal(secret1))

			// write new value and invalidate cache after short timeout to allow modinfo time to change
			time.Sleep(20 * time.Millisecond)
			if err := ioutil.WriteFile(keyfile.Name(), secret2, os.ModePerm); err != nil {
				Fail("Unexpected error overwriting keyfile in cache invalidation test")
			}
			key2 := b.GetHMACSecret()
			Expect(key2).To(Equal(secret2))

		})

		It("should detect invalid configurations of auth backends", func() {
			os.Unsetenv("JWT_PUBLIC_KEY")
			os.Unsetenv("JWT_SECRET")

			b := backend{}
			v := b.IsConfigValid()
			Expect(v).To(BeFalse())

			os.Setenv("JWT_SECRET", "secret")
			os.Setenv("JWT_PUBLIC_KEY", rsaPublicKey)
			v2 := b.IsConfigValid()
			Expect(v2).To(BeFalse())
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

	Describe("Find tokens in the request", func() {

		It("should return the token if set in the Auhorization header", func() {
			req, _ := http.NewRequest("GET", "/testing", nil)
			req.Header.Set("Authorization", strings.Join([]string{"Bearer", validToken}, " "))
			token, err := ExtractToken(req)
			Expect(err).To(BeNil())
			Expect(token).To(Equal(validToken))
		})

		It("should return the token if set in a cookie", func() {
			req, _ := http.NewRequest("GET", "/testing", nil)
			req.AddCookie(&http.Cookie{Name: "jwt_token", Value: validToken})
			token, err := ExtractToken(req)
			Expect(err).To(BeNil())
			Expect(token).To(Equal(validToken))
		})

		It("should return the token if set as query parameter", func() {
			url := strings.Join([]string{"/testing?token=", validToken}, "")
			req, _ := http.NewRequest("GET", url, nil)
			token, err := ExtractToken(req)
			Expect(err).To(BeNil())
			Expect(token).To(Equal(validToken))
		})

	})

	Describe("Validate tokens in accordance with the JWT standard", func() {

		It("should validate a correctly formed token", func() {
			if err := os.Setenv("JWT_SECRET", "secret"); err != nil {
				Fail("unexpected error setting JWT_SECRET")
			}
			os.Unsetenv("JWT_PUBLIC_KEY")
			token := jwt.New(jwt.SigningMethodHS256)
			token.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 1).Unix()
			sToken, err := token.SignedString([]byte("secret"))
			if err != nil {
				Fail(fmt.Sprintf("unexpected error constructing token: %s", err))
			}
			b := backend{}
			vToken, err := ValidateToken(sToken, b)

			Expect(err).To(BeNil())
			Expect(vToken.Valid).To(Equal(true))
		})

		It("should validate a correctly formed RSA token", func() {
			os.Unsetenv("JWT_SECRET")
			if err := os.Setenv("JWT_PUBLIC_KEY", rsaPublicKey); err != nil {
				Fail("unexpected error setting JWT_PUBLIC_KEY")
			}
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

			b := backend{}
			vToken, err := ValidateToken(sToken, b)

			Expect(err).To(BeNil())
			Expect(vToken.Valid).To(Equal(true))
		})

		It("should not validate a incorrectly formed token", func() {
			if err := os.Setenv("JWT_SECRET", "secret"); err != nil {
				Fail("unexpected error setting JWT_SECRET")
			}
			os.Unsetenv("JWT_PUBLIC_KEY")
			token := jwt.New(jwt.SigningMethodHS256)
			token.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 1).Unix()
			sToken, err := token.SignedString([]byte("notsecret"))
			if err != nil {
				Fail(fmt.Sprintf("unexpected error constructing token: %s", err))
			}

			b := backend{}
			vToken, err := ValidateToken(sToken, b)

			Expect(err).To(HaveOccurred())
			Expect(vToken).To(BeNil())
		})

		It("should not validate a malformed token", func() {

			b := backend{}
			vToken, err := ValidateToken(malformedToken, b)

			Expect(err).To(HaveOccurred())
			Expect(vToken).To(BeNil())
		})

		It("should not validate a token with an expired timestamp", func() {
			if err := os.Setenv("JWT_SECRET", "secret"); err != nil {
				Fail("unexpected error setting JWT_SECRET")
			}
			os.Unsetenv("JWT_PUBLIC_KEY")
			token := jwt.New(jwt.SigningMethodHS256)
			token.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * -1).Unix()
			sToken, err := token.SignedString([]byte("secret"))
			if err != nil {
				Fail(fmt.Sprintf("unexpected error constructing token: %s", err))
			}

			b := backend{}
			vToken, err := ValidateToken(sToken, b)

			Expect(err).To(HaveOccurred())
			Expect(vToken).To(BeNil())
		})

		It("should not allow JWT with algorithm none", func() {
			if err := os.Setenv("JWT_SECRET", "secret"); err != nil {
				Fail("unexpected error setting JWT_SECRET")
			}
			os.Unsetenv("JWT_PUBLIC_KEY")
			token := jwt.New(jwt.SigningMethodHS256)
			token.Header["alg"] = "none"
			token.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 1).Unix()
			sToken, err := token.SignedString([]byte("secret"))
			if err != nil {
				Fail(fmt.Sprintf("unexpected error constructing token: %s", err))
			}

			b := backend{}
			vToken, err := ValidateToken(sToken, b)

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
	Describe("Function correctly as an authorization middleware", func() {
		rw := Auth{
			Next: httpserver.HandlerFunc(passThruHandler),
			Rules: []Rule{
				Rule{Path: "/testing", ExceptedPaths: []string{"/testing/excepted"}},
			},
			Realm: "testing.com",
		}

		if err := os.Setenv("JWT_SECRET", "secret"); err != nil {
			Fail("unexpected error setting JWT_SECRET")
		}
		if err := os.Unsetenv("JWT_PUBLIC_KEY"); err != nil {
			Fail("unexpected error unsetting JWT_PUBLIC_KEY")
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
			rw := Auth{
				Next: httpserver.HandlerFunc(passThruHandler),
				Rules: []Rule{
					Rule{Path: "/testing", ExceptedPaths: []string{"/testing/excepted"}, StripHeader: true},
				},
				Realm: "testing.com",
			}

			if err := os.Setenv("JWT_SECRET", "secret"); err != nil {
				Fail("unexpected error setting JWT_SECRET")
			}
			if err := os.Unsetenv("JWT_PUBLIC_KEY"); err != nil {
				Fail("unexpected error unsetting JWT_PUBLIC_KEY")
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
			ruleAllowUser := Rule{Path: "/testing", AccessRules: []AccessRule{accessRuleAllowUser}}
			ruleDenyRole := Rule{Path: "/testing", AccessRules: []AccessRule{accessRuleDenyRole}}
			ruleAllowRoleAllowUser := []Rule{Rule{Path: "/testing", AccessRules: []AccessRule{accessRuleAllowRole, accessRuleAllowUser}}}
			ruleDenyRoleAllowUser := []Rule{Rule{Path: "/testing", AccessRules: []AccessRule{accessRuleDenyRole, accessRuleAllowUser}}}
			if err := os.Setenv("JWT_SECRET", "secret"); err != nil {
				Fail("Could not set environment secret")
			}
			if err := os.Unsetenv("JWT_PUBLIC_KEY"); err != nil {
				Fail("Could not unset secret")
			}

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
			}}
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
				defer os.Remove(key1)
				key2, err := createKeyFile("notvalidkey")
				if err != nil {
					Fail(fmt.Sprintf("unexpected error creating key file: %s", err))
				}
				defer os.Remove(key2)

				token := genRSAToken(rsaPrivateKey, map[string]interface{}{"test": "test"})

				rw := Auth{
					Next:  httpserver.HandlerFunc(passThruHandler),
					Rules: []Rule{{Path: "/testing", KeyFile: []string{key1, key2}, KeyFileType: RSA}},
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
				defer os.Remove(key1)
				key2, err := createKeyFile("notvalidkey")
				if err != nil {
					Fail(fmt.Sprintf("unexpected error creating key file: %s", err))
				}
				defer os.Remove(key2)

				token := genRSAToken(rsaPrivateKey, map[string]interface{}{"test": "test"})

				rw := Auth{
					Next:  httpserver.HandlerFunc(passThruHandler),
					Rules: []Rule{{Path: "/testing", KeyFile: []string{key2, key2, key2, key1}, KeyFileType: RSA}},
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
				defer os.Remove(key2)

				token := genRSAToken(rsaPrivateKey, map[string]interface{}{"test": "test"})

				rw := Auth{
					Next:  httpserver.HandlerFunc(passThruHandler),
					Rules: []Rule{{Path: "/testing", KeyFile: []string{key2, key2, key2}, KeyFileType: RSA}},
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
