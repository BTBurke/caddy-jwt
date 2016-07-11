package jwt

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func (h JWTAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	// if the request path is any of the configured paths, validate JWT
	for _, p := range h.Rules {
		if !httpserver.Path(r.URL.Path).Matches(p.Path) {
			continue
		}

		// Path matches, look for unvalidated token
		uToken, err := ExtractToken(r)
		if err != nil {
			return http.StatusUnauthorized, nil
		}

		// Validate token
		vToken, err := ValidateToken(uToken)
		if err != nil {
			return http.StatusUnauthorized, nil
		}
		vClaims := vToken.Claims.(jwt.MapClaims)

		// If token contains rules with allow or deny, evaluate
		if len(p.AccessRules) > 0 {
			var isAuthorized []bool
			for _, rule := range p.AccessRules {
				switch rule.Authorize {
				case ALLOW:
					if vClaims[rule.Claim] == rule.Value {
						isAuthorized = append(isAuthorized, true)
					}
					if vClaims[rule.Claim] != rule.Value {
						isAuthorized = append(isAuthorized, false)
					}
				case DENY:
					if vClaims[rule.Claim] == rule.Value {
						isAuthorized = append(isAuthorized, false)
					}
					if vClaims[rule.Claim] != rule.Value {
						isAuthorized = append(isAuthorized, true)
					}
				default:
					return http.StatusUnauthorized, fmt.Errorf("unknown rule type")
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
				return http.StatusUnauthorized, nil
			}
		}

		// set claims as separate headers for downstream to consume
		for claim, value := range vClaims {
			c := strings.ToUpper(claim)
			switch value.(type) {
			case string:
				r.Header.Set(strings.Join([]string{"Token-Claim-", c}, ""), value.(string))
			case int64:
				r.Header.Set(strings.Join([]string{"Token-Claim-", c}, ""), strconv.FormatInt(value.(int64), 10))
			case bool:
				r.Header.Set(strings.Join([]string{"Token-Claim-", c}, ""), strconv.FormatBool(value.(bool)))
			case int32:
				r.Header.Set(strings.Join([]string{"Token-Claim-", c}, ""), strconv.FormatInt(int64(value.(int32)), 10))
			case float32:
				r.Header.Set(strings.Join([]string{"Token-Claim-", c}, ""), strconv.FormatFloat(float64(value.(float32)), 'f', -1, 32))
			case float64:
				r.Header.Set(strings.Join([]string{"Token-Claim-", c}, ""), strconv.FormatFloat(value.(float64), 'f', -1, 64))
			default:
				return http.StatusUnauthorized, fmt.Errorf("unknown claim type, unable to convert to string")
			}
		}
		// pass raw token in case downstream wants to do more sophisticated processing
		r.Header.Set("Token", vToken.Raw)
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

// ValidateToken will return a parsed token if it passes validation, or an
// error if any part of the token fails validation.  Possible errors include
// malformed tokens, unknown/unspecified signing algorithms, missing secret key,
// tokens that are not valid yet (i.e., 'nbf' field), tokens that are expired,
// and tokens that fail signature verification (forged)
func ValidateToken(uToken string) (*jwt.Token, error) {
	if len(uToken) == 0 {
		return nil, fmt.Errorf("Token length is zero")
	}

	token, err := jwt.Parse(uToken, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", t.Header["alg"])
		}
		secret, err := lookupSecret()
		if err != nil {
			return nil, err
		}
		return secret, nil
	})

	if token.Valid && err == nil {
		return token, nil
	}
	// if token not valid, err can be inspected to get more information about which
	// part failed validation
	return nil, err
}

// JWT signing token must be set as environment variable JWT_SECRET and not
// be the empty string
func lookupSecret() ([]byte, error) {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		return nil, fmt.Errorf("JWT_SECRET not set")
	}
	return []byte(secret), nil
}
