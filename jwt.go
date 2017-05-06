package jwt

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	"bytes"

	"github.com/dgrijalva/jwt-go"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

type JWTAuthBackend interface {
	GetHMACSecret() (b []byte)
	GetRSAPublicKey() (r *rsa.PublicKey)
	IsConfigValid() (v bool)
}

func (h JWTAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	// if the request path is any of the configured paths, validate JWT
	for _, p := range h.Rules {
		if !httpserver.Path(r.URL.Path).Matches(p.Path) {
			continue
		}

		// Check excepted paths for this rule and allow access without validating any token
		var isExceptedPath bool
		for _, e := range p.ExceptedPaths {
			if httpserver.Path(r.URL.Path).Matches(e) {
				isExceptedPath = true
			}
		}
		if isExceptedPath {
			continue
		}
		if r.URL.Path == "/" && p.AllowRoot {
			// special case for protecting children of the root path, only allow access to base directory with directive `allowbase`
			continue
		}

		// Path matches, look for unvalidated token
		uToken, err := ExtractToken(r)
		if err != nil {
			return handleUnauthorized(w, r, p, h.Realm), nil
		}

		backend := backend{}
		// Validate token
		vToken, err := ValidateToken(uToken, backend)
		if err != nil {
			return handleUnauthorized(w, r, p, h.Realm), nil
		}
		vClaims, err := Flatten(vToken.Claims.(jwt.MapClaims), "", DotStyle)
		if err != nil {
			return handleUnauthorized(w, r, p, h.Realm), nil
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
					return handleUnauthorized(w, r, p, h.Realm), fmt.Errorf("unknown rule type")
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
				return handleForbidden(w, r, p, h.Realm), nil
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

// ValidateToken will return a parsed token if it passes validation, or an
// error if any part of the token fails validation.  Possible errors include
// malformed tokens, unknown/unspecified signing algorithms, missing secret key,
// tokens that are not valid yet (i.e., 'nbf' field), tokens that are expired,
// and tokens that fail signature verification (forged)
func ValidateToken(uToken string, b JWTAuthBackend) (*jwt.Token, error) {
	if len(uToken) == 0 {
		return nil, fmt.Errorf("Token length is zero")
	}

	if !b.IsConfigValid() {
		return nil, errors.New("No valid configuration for JWT validation found")
	}

	hmac := b.GetHMACSecret()
	rsa := b.GetRSAPublicKey()

	switch {
	case hmac != nil:
		token, err := jwt.Parse(uToken, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("HMAC: Unexpected signing method: %v", t.Header["alg"])
			}
			return hmac, nil
		})

		if err != nil {
			return nil, err
		}

		return token, nil

	case rsa != nil:
		token, err := jwt.Parse(uToken, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("RSA: Unexpected signing method: %v", t.Header["alg"])
			}
			return rsa, nil
		})
		if err != nil {
			return nil, err
		}

		return token, nil
	default:
		return nil, errors.New("No valid configuration for JWT validation found")
	}

}

type backend struct{}

// JWT signing token must be set as environment variable JWT_SECRET and not
// be the empty string
func (b backend) GetHMACSecret() []byte {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		return nil
	}
	return []byte(secret)
}

func (b backend) GetRSAPublicKey() *rsa.PublicKey {
	pem := os.Getenv("JWT_PUBLIC_KEY")
	if pem == "" {
		return nil
	}
	rsaPub, err := jwt.ParseRSAPublicKeyFromPEM([]byte(pem))
	if err != nil {
		return nil
	}
	return rsaPub
}

func (b backend) IsConfigValid() bool {

	hmac := b.GetHMACSecret()
	rsa := b.GetRSAPublicKey()

	switch {
	case hmac != nil && rsa == nil:
		return true
	case hmac == nil && rsa != nil:
		return true
	default:
		return false
	}
}

// handleUnauthorized checks, which action should be performed if access was denied.
// It returns the status code and writes the Location header in case of a redirect.
// Possible caddy variables in the location value will be substituted.
func handleUnauthorized(w http.ResponseWriter, r *http.Request, rule Rule, realm string) int {
	if rule.Redirect != "" {
		replacer := httpserver.NewReplacer(r, nil, "")
		http.Redirect(w, r, replacer.Replace(rule.Redirect), http.StatusSeeOther)
		return http.StatusSeeOther
	}

	w.Header().Add("WWW-Authenticate", fmt.Sprintf("Bearer realm=\"%s\",error=\"invalid_token\"", realm))
	return http.StatusUnauthorized
}

// handleForbidden checks, which action should be performed if access was denied.
// It returns the status code and writes the Location header in case of a redirect.
// Possible caddy variables in the location value will be substituted.
func handleForbidden(w http.ResponseWriter, r *http.Request, rule Rule, realm string) int {
	if rule.Redirect != "" {
		replacer := httpserver.NewReplacer(r, nil, "")
		http.Redirect(w, r, replacer.Replace(rule.Redirect), http.StatusSeeOther)
		return http.StatusSeeOther
	}
	w.Header().Add("WWW-Authenticate", fmt.Sprintf("Bearer realm=\"%s\",error=\"insufficient_scope\"", realm))
	return http.StatusForbidden
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
