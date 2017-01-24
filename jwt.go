package jwt

import (
	"crypto/rsa"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	"bytes"

	"github.com/dgrijalva/jwt-go"
	"github.com/jeremywohl/flatten"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

type JWTAuthBackend struct {
	HMACSecret   []byte
	RSAPublicKey *rsa.PublicKey
}

var authBackendInstance *JWTAuthBackend = nil

func (h JWTAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	// if the request path is any of the configured paths, validate JWT
	for _, p := range h.Rules {
		if !httpserver.Path(r.URL.Path).Matches(p.Path) {
			continue
		}

		// Path matches, look for unvalidated token
		uToken, err := ExtractToken(r)
		if err != nil {
			return handleUnauthorized(w, r, p), nil
		}

		// Validate token
		vToken, err := ValidateToken(uToken)
		if err != nil {
			return handleUnauthorized(w, r, p), nil
		}
		vClaims, err := flatten.Flatten(vToken.Claims.(jwt.MapClaims), "", flatten.DotStyle)
		if err != nil {
			return handleUnauthorized(w, r, p), nil
		}

		// If token contains rules with allow or deny, evaluate
		if len(p.AccessRules) > 0 {
			var isAuthorized []bool
			for _, rule := range p.AccessRules {
				v := vClaims[rule.Claim]
				ruleMatches := contains(v, rule.Value) || v == rule.Value
				switch rule.Authorize {
				case ALLOW:
					isAuthorized = append(isAuthorized, ruleMatches)
				case DENY:
					isAuthorized = append(isAuthorized, !ruleMatches)
				default:
					return handleUnauthorized(w, r, p), fmt.Errorf("unknown rule type")
				}
			}
			// test all flags, if any are true then ok to pass
			ok := false
			for _, result := range isAuthorized {
				if result {
					ok = true
				}
			}
			if !ok {
				return handleUnauthorized(w, r, p), nil
			}
		}

		// set claims as separate headers for downstream to consume
		for claim, value := range vClaims {
			headerName := "Token-Claim-" + strings.ToUpper(claim)
			switch v := value.(type) {
			case string:
				r.Header.Set(headerName, v)
			case int64:
				r.Header.Set(headerName, strconv.FormatInt(v, 10))
			case bool:
				r.Header.Set(headerName, strconv.FormatBool(v))
			case int32:
				r.Header.Set(headerName, strconv.FormatInt(int64(v), 10))
			case float32:
				r.Header.Set(headerName, strconv.FormatFloat(float64(v), 'f', -1, 32))
			case float64:
				r.Header.Set(headerName, strconv.FormatFloat(v, 'f', -1, 64))
			case []interface{}:
				b := bytes.NewBufferString("")
				for i, item := range v {
					if i > 0 {
						b.WriteString(",")
					}
					b.WriteString(fmt.Sprintf("%v", item))
				}
				r.Header.Set(headerName, b.String())
			default:
				// ignore, because, JWT spec says in https://tools.ietf.org/html/rfc7519#section-4
				//     all claims that are not understood
				//     by implementations MUST be ignored.
			}
		}

		return h.Next.ServeHTTP(w, r)
	}
	// pass request if no paths protected with JWT
	return h.Next.ServeHTTP(w, r)
}

// ExtractToken will find a JWT token passed one of three ways: (1) as the Authorization
// header in the form `Bearer <JWT Token>`; (2) as a cookie named `jwt_token`; (3) as
// a URL query paramter of the form https://example.com?token=<JWT token>
func ExtractToken(r *http.Request) (string, error) {
	jwtHeader := strings.Split(r.Header.Get("Authorization"), " ")
	if jwtHeader[0] == "Bearer" && len(jwtHeader) == 2 {
		return jwtHeader[1], nil
	}

	jwtCookie, err := r.Cookie("jwt_token")
	if err == nil {
		return jwtCookie.Value, nil
	}

	jwtQuery := r.URL.Query().Get("token")
	if jwtQuery != "" {
		return jwtQuery, nil
	}

	return "", fmt.Errorf("no token found")
}

func InitJWTAuthBackend() *JWTAuthBackend {
	if authBackendInstance == nil {
		authBackendInstance = &JWTAuthBackend{
			HMACSecret:   lookupSecret(),
			RSAPublicKey: getPublicKey(),
		}
	}
	return authBackendInstance
}

// ValidateToken will return a parsed token if it passes validation, or an
// error if any part of the token fails validation.  Possible errors include
// malformed tokens, unknown/unspecified signing algorithms, missing secret key,
// tokens that are not valid yet (i.e., 'nbf' field), tokens that are expired,
// and tokens that fail signature verification (forged)
func ValidateToken(uToken string) (*jwt.Token, error) {
	if len(uToken) == 0 {
		return nil, fmt.Errorf("Token length is zero")
	}

	authBackend := InitJWTAuthBackend()

	if authBackend.HMACSecret != nil {
		token, err := jwt.Parse(uToken, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", t.Header["alg"])
			}
			return authBackend.HMACSecret, nil
		})

		if err != nil {
			return nil, err
		}

		return token, nil
	}
	if authBackend.RSAPublicKey != nil {
		token, err := jwt.Parse(uToken, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", t.Header["alg"])
			}
			return authBackend.RSAPublicKey, nil
		})

		// if token is malformed or invalid, err can be inspected to get more information
		// about which validation part failed
		if err != nil {
			return nil, err
		}

		return token, nil
	}
	// if token not valid, err can be inspected to get more information about which
	// part failed validation
	return nil, fmt.Errorf("JWT_SECRET nor JWT_PUBLIC_KEY is set")
}

// JWT signing token must be set as environment variable JWT_SECRET and not
// be the empty string
func lookupSecret() []byte {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		return nil
	}
	return []byte(secret)
}

func getPublicKey() *rsa.PublicKey {
	pem := os.Getenv("JWT_PUBLIC_KEY")
	if pem == "" {
		return nil
	}
	rsaPub, err := jwt.ParseRSAPublicKeyFromPEM([]byte(pem))
	if err != nil {
		panic(err)
	}
	return rsaPub
}

// handleUnauthorized checks, which action should be performed if access was denied.
// It returns the status code and writes the Location header in case of a redirect.
// Possible caddy variables in the location value will be substituted.
func handleUnauthorized(w http.ResponseWriter, r *http.Request, rule Rule) int {
	if rule.Redirect != "" {
		replacer := httpserver.NewReplacer(r, nil, "")
		http.Redirect(w, r, replacer.Replace(rule.Redirect), http.StatusSeeOther)
		return http.StatusSeeOther
	}
	return http.StatusUnauthorized
}

// contains checks weather list is a slice ans containts the
// supplied string value.
func contains(list interface{}, value string) bool {
	switch l := list.(type) {
	case []interface{}:
		for _, v := range l {
			if v == value {
				return true
			}
		}
	}
	return false
}
