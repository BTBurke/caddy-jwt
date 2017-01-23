package jwt

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/mholt/caddy/caddyhttp/httpserver"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

const (
	validToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"
	malformedToken = "loremIpsum"
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

var _ = Describe("JWTAuth", func() {
	Describe("Use environment to get secrets", func() {

		It("should get the JWT secret from the environment JWT_SECRET", func() {
			if err := os.Setenv("JWT_SECRET", "secret"); err != nil {
				Fail("Unexpected error setting JWT_SECRET")
			}
			secret, err := lookupSecret()
			Expect(secret).To(Equal([]byte("secret")))
			Expect(err).To(BeNil())
		})

		It("should return an error JWT_SECRET not set", func() {
			if err := os.Setenv("JWT_SECRET", ""); err != nil {
				Fail("Unexpected error setting JWT_SECRET")
			}
			secret, err := lookupSecret()
			Expect(secret).To(BeNil())
			Expect(err).To(HaveOccurred())
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
			token := jwt.New(jwt.SigningMethodHS256)
			token.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 1).Unix()
			sToken, err := token.SignedString([]byte("secret"))
			if err != nil {
				Fail(fmt.Sprintf("unexpected error constructing token: %s", err))
			}

			vToken, err := ValidateToken(sToken)

			Expect(err).To(BeNil())
			Expect(vToken.Valid).To(Equal(true))
		})

		It("should not validate a incorrectly formed token", func() {
			if err := os.Setenv("JWT_SECRET", "secret"); err != nil {
				Fail("unexpected error setting JWT_SECRET")
			}
			token := jwt.New(jwt.SigningMethodHS256)
			token.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 1).Unix()
			sToken, err := token.SignedString([]byte("notsecret"))
			if err != nil {
				Fail(fmt.Sprintf("unexpected error constructing token: %s", err))
			}

			vToken, err := ValidateToken(sToken)

			Expect(err).To(HaveOccurred())
			Expect(vToken).To(BeNil())
		})

		It("should not validate a malformed token", func() {

			vToken, err := ValidateToken(malformedToken)

			Expect(err).To(HaveOccurred())
			Expect(vToken).To(BeNil())
		})

		It("should not validate a token with an expired timestamp", func() {
			if err := os.Setenv("JWT_SECRET", "secret"); err != nil {
				Fail("unexpected error setting JWT_SECRET")
			}
			token := jwt.New(jwt.SigningMethodHS256)
			token.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * -1).Unix()
			sToken, err := token.SignedString([]byte("secret"))
			if err != nil {
				Fail(fmt.Sprintf("unexpected error constructing token: %s", err))
			}

			vToken, err := ValidateToken(sToken)

			Expect(err).To(HaveOccurred())
			Expect(vToken).To(BeNil())
		})

		It("should not allow JWT with algorithm none", func() {
			if err := os.Setenv("JWT_SECRET", "secret"); err != nil {
				Fail("unexpected error setting JWT_SECRET")
			}
			token := jwt.New(jwt.SigningMethodHS256)
			token.Header["alg"] = "none"
			token.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 1).Unix()
			sToken, err := token.SignedString([]byte("secret"))
			if err != nil {
				Fail(fmt.Sprintf("unexpected error constructing token: %s", err))
			}

			vToken, err := ValidateToken(sToken)

			Expect(err).To(HaveOccurred())
			Expect(vToken).To(BeNil())
		})
	})
	Describe("Redirect on access deny works", func() {
		It("return 303 when a redirect is configured and access denied", func() {
			req, err := http.NewRequest("GET", "/testing", nil)

			rec := httptest.NewRecorder()
			rw := JWTAuth{
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
			rw := JWTAuth{
				Rules: []Rule{{Path: "/testing", Redirect: "/login?backTo={uri}"}},
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
		rw := JWTAuth{
			Next:  httpserver.HandlerFunc(passThruHandler),
			Rules: []Rule{Rule{Path: "/testing"}},
		}

		if err := os.Setenv("JWT_SECRET", "secret"); err != nil {
			Fail("unexpected error setting JWT_SECRET")
		}
		token := jwt.New(jwt.SigningMethodHS256)
		token.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 1).Unix()
		token.Claims.(jwt.MapClaims)["user"] = "test"
		token.Claims.(jwt.MapClaims)["int32"] = int32(10)
		token.Claims.(jwt.MapClaims)["float32"] = float32(3.14159)
		token.Claims.(jwt.MapClaims)["float64"] = float64(3.14159)
		token.Claims.(jwt.MapClaims)["bool"] = true
		token.Claims.(jwt.MapClaims)["list"] = []string{"foo", "bar", "bazz"}

		validToken, err := token.SignedString([]byte("secret"))
		if err != nil {
			Fail(fmt.Sprintf("unexpected error constructing token: %s", err))
		}

		invalidToken, err := token.SignedString([]byte("notsecret"))
		if err != nil {
			Fail(fmt.Sprintf("unexpected error constructing token: %s", err))
		}

		It("return 401 when the token is not valid and the path is protected", func() {
			req, err := http.NewRequest("GET", "/testing", nil)
			req.Header.Set("Authorization", strings.Join([]string{"Bearer", invalidToken}, " "))

			rec := httptest.NewRecorder()
			result, err := rw.ServeHTTP(rec, req)
			if err != nil {
				Fail(fmt.Sprintf("unexpected error constructing server: %s", err))
			}

			Expect(result).To(Equal(http.StatusUnauthorized))
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
				"Token-Claim-User":    "test",
				"Token-Claim-Bool":    "true",
				"Token-Claim-Float32": "3.14159",
				"Token-Claim-Float64": "3.14159",
				"Token-Claim-Int32":   "10",
				"Token-Claim-List":    "foo,bar,bazz",
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
			It("should allow authorization based on a specific claim value", func() {
				rw := JWTAuth{
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
				rw := JWTAuth{
					Next:  httpserver.HandlerFunc(passThruHandler),
					Rules: []Rule{ruleAllowUser},
				}

				req, err := http.NewRequest("GET", "/testing", nil)
				req.Header.Set("Authorization", strings.Join([]string{"Bearer", tokenNotUser}, " "))

				rec := httptest.NewRecorder()
				result, err := rw.ServeHTTP(rec, req)
				if err != nil {
					Fail(fmt.Sprintf("unexpected error constructing server: %s", err))
				}

				Expect(result).To(Equal(http.StatusUnauthorized))
			})
			It("should correctly apply rules in order with multiple ALLOWs", func() {
				// tests situation where user is denied based on wrong role
				// but subsequent allow based on username is ok
				rw := JWTAuth{
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
				rw := JWTAuth{
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
				rw := JWTAuth{
					Next:  httpserver.HandlerFunc(passThruHandler),
					Rules: []Rule{ruleDenyRole},
				}

				req, err := http.NewRequest("GET", "/testing", nil)
				req.Header.Set("Authorization", strings.Join([]string{"Bearer", tokenUser}, " "))

				rec := httptest.NewRecorder()
				result, err := rw.ServeHTTP(rec, req)
				if err != nil {
					Fail(fmt.Sprintf("unexpected error constructing server: %s", err))
				}

				Expect(result).To(Equal(http.StatusUnauthorized))
			})

			It("should allow based on no match to DENY", func() {
				// tests situation where user is denied based on wrong role
				// but subsequent allow based on username is ok
				rw := JWTAuth{
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
			It("should allow claim values, which are part of a list", func() {
				rw := JWTAuth{
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
				rw := JWTAuth{
					Next:  httpserver.HandlerFunc(passThruHandler),
					Rules: []Rule{ruleAllowUser},
				}

				req, err := http.NewRequest("GET", "/testing", nil)
				req.Header.Set("Authorization", strings.Join([]string{"Bearer", tokenGroupsOperator}, " "))

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
