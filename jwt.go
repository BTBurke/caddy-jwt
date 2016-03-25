package jwt

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/mholt/caddy/caddy/setup"
	"github.com/mholt/caddy/middleware"
)

type JWTAuth struct {
	Paths []string
	Next  middleware.Handler
}

func (h JWTAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	// if the request path is any of the configured paths, validate JWT
	for _, p := range h.Paths {
		if !middleware.Path(r.URL.Path).Matches(p) {
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

		// set claims as separate headers for downstream to consume
		for claim, value := range vToken.Claims {
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

func Setup(c *setup.Controller) (middleware.Middleware, error) {
	paths, err := parse(c)
	if err != nil {
		return nil, err
	}

	// On Caddy startup checks for JWT_SECRET. Warn only if not present since
	// separate authentication function may set this value when creating first
	// token.
	c.Startup = append(c.Startup, func() error {
		secret := os.Getenv("JWT_SECRET")
		if secret == "" {
			fmt.Println("WARN: JWT secret not set. Will return 401 unauthorized until secret set in environment variable JWT_SECRET")
		}
		fmt.Println("JWT middleware is initiated")
		return nil
	})

	return func(next middleware.Handler) middleware.Handler {
		return &JWTAuth{
			Paths: paths,
			Next:  next,
		}
	}, nil
}

func parse(c *setup.Controller) ([]string, error) {
	// This parses the following config blocks
	/*
		jwt /hello
		jwt /anotherpath
		jwt {
			path /hello
			path /anotherpath
		}
	*/
	var paths []string
	for c.Next() {
		args := c.RemainingArgs()
		switch len(args) {
		case 0:
			// no argument passed, check the config block
			for c.NextBlock() {
				switch c.Val() {
				case "path":
					if !c.NextArg() {
						// we are expecting a value
						return paths, c.ArgErr()
					}
					p := c.Val()
					paths = append(paths, p)
					if c.NextArg() {
						// we are expecting only one value.
						return paths, c.ArgErr()
					}
				}
			}
		case 1:
			// one argument passed
			paths = append(paths, args[0])
			if c.NextBlock() {
				// path specified, no block required.
				return paths, c.ArgErr()
			}
		default:
			// we want only one argument max
			return paths, c.ArgErr()
		}
	}
	return paths, nil
}
