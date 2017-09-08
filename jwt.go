package jwt

import (
	"bytes"
	"crypto/rsa"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
	"regexp"

	"github.com/dgrijalva/jwt-go"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

// global declaration of the backend to enable caching secret key material across requests
// when keys are specified in the config file
var b = backend{
	cache: make(map[string]keycache),
}

// AuthBackend represents a backend interface that retrieves secret key material
// to validate tokens
type AuthBackend interface {
	GetHMACSecret() (b []byte)
	GetRSAPublicKey() (r *rsa.PublicKey)
	IsConfigValid() (v bool)
}

func (h Auth) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	// if the request path is any of the configured paths, validate JWT
	for _, p := range h.Rules {
		
		// TODO: this is a hack to work our CVE in Caddy dealing with parsing
		// malformed URLs.  Can be removed once upstream fix for path match
		if r.URL.EscapedPath() == "" {
			return handleUnauthorized(w, r, p, h.Realm), nil
		}
		re := regexp.MustCompile("/+")
		cleanedPath := re.ReplaceAllString(r.URL.Path, "/")
		if !httpserver.Path(cleanedPath).Matches(p.Path) {
			continue
		}

        if r.Method == "OPTIONS" {
            continue
        }

		// strip potentially spoofed claims
		for header, _ := range r.Header {
			if strings.HasPrefix(header, "Token-Claim-") {
				r.Header.Del(header)
			}
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
			if p.Passthrough {
				continue
			}
			return handleUnauthorized(w, r, p, h.Realm), nil
		}

		var vToken *jwt.Token

		switch {
		case len(p.KeyFile) > 0:

			// Loop through all possible key files on disk, using cache
			for _, keyfile := range p.KeyFile {
				// Initialize a new caching layer if this is the first request to a protected path.
				// Cache only operates when key material is stored on disk.  When using environment variables
				// this has no effect.
				_, ok := b.cache[keyfile]
				if !ok {
					b.cache[keyfile] = keycache{
						KeyFile:     keyfile,
						KeyFileType: p.KeyFileType,
					}
				}
				b.current = b.cache[keyfile]

				// Validate token
				vToken, err = ValidateToken(uToken, b)

				if err == nil {
					// break on first correctly validated token
					break
				}
			}

			// Check last error of validating token.  If error still exists, no keyfiles matched
			if err != nil || vToken == nil {
				if p.Passthrough {
					continue
				}
				return handleUnauthorized(w, r, p, h.Realm), nil
			}
		default:
			// when no keyfiles, use environment variables, clear cache first
			b.current = keycache{}
			vToken, err = ValidateToken(uToken, b)

			if err != nil {
				if p.Passthrough {
					continue
				}
				return handleUnauthorized(w, r, p, h.Realm), nil
			}
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
			var headerName string
			switch p.StripHeader {
			case true:
				stripped := strings.SplitAfter(claim, "/")
				finalStrip := stripped[len(stripped)-1]
				headerName = "Token-Claim-" + modTitleCase(finalStrip)
			default:
				escaped := url.PathEscape(claim)
				headerName = "Token-Claim-" + modTitleCase(escaped)
			}

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
func ValidateToken(uToken string, b AuthBackend) (*jwt.Token, error) {
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

type backend struct {
	current keycache
	cache   map[string]keycache
}

type keycache struct {
	KeyFile     string
	KeyFileType EncryptionType
	Key         []byte
	ModifyTime  time.Time
}

func (b backend) GetHMACSecret() []byte {
	switch b.current.KeyFileType {
	case RSA:
		return nil
	case HMAC:
		if secret, err := readKeyFromFile(&b); err == nil {
			return secret
		}
		secret := os.Getenv("JWT_SECRET")
		if secret == "" {
			return nil
		}
		return []byte(secret)
	default:
		secret := os.Getenv("JWT_SECRET")
		if secret == "" {
			return nil
		}
		return []byte(secret)
	}
}

func (b backend) GetRSAPublicKey() *rsa.PublicKey {

	switch b.current.KeyFileType {
	case HMAC:
		return nil
	case RSA:
		if pem, err := readKeyFromFile(&b); err == nil {
			rsaPub, err := jwt.ParseRSAPublicKeyFromPEM([]byte(pem))
			if err != nil {
				return nil
			}
			return rsaPub
		}
		pem := os.Getenv("JWT_PUBLIC_KEY")
		if pem == "" {
			return nil
		}
		rsaPub, err := jwt.ParseRSAPublicKeyFromPEM([]byte(pem))
		if err != nil {
			return nil
		}
		return rsaPub
	default:
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

// readKeyFromFile attempts to read key material from the path specified in the config.
// If the path is not absolute it will attempt to find it as a relative path from the
// working directory.  To prevent issues with concurrent read/write to the filesystem
// on every request, it will cache the result of the file read and only re-read the file
// when the modification time is earlier than the cached value
func readKeyFromFile(b *backend) ([]byte, error) {

	var keyfilePath string
	if path.IsAbs(b.current.KeyFile) {
		keyfilePath = b.current.KeyFile
	} else {
		wd, err := os.Getwd()
		if err != nil {
			return nil, err
		}
		keyfilePath = path.Join(wd, b.current.KeyFile)
	}

	finfo, err := os.Stat(keyfilePath)
	if os.IsNotExist(err) {
		return nil, err
	}

	cachehit, ok := b.cache[b.current.KeyFile]
	if !ok {
		key, err := ioutil.ReadFile(keyfilePath)
		if err != nil {
			return nil, err
		}

		b.cache[b.current.KeyFile] = keycache{
			KeyFile:     b.current.KeyFile,
			KeyFileType: b.current.KeyFileType,
			Key:         key,
			ModifyTime:  finfo.ModTime(),
		}
		b.current = b.cache[b.current.KeyFile]
		return key, nil
	}

	if finfo.ModTime().After(cachehit.ModifyTime) {
		key, err := ioutil.ReadFile(keyfilePath)
		if err != nil {
			return nil, err
		}
		b.cache[b.current.KeyFile] = keycache{
			KeyFile:     b.current.KeyFile,
			KeyFileType: b.current.KeyFileType,
			Key:         key,
			ModifyTime:  finfo.ModTime(),
		}
		b.current = b.cache[b.current.KeyFile]
		return key, nil
	}

	return cachehit.Key, nil
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

func modTitleCase(s string) string {
	switch {
	case len(s) == 0:
		return s
	case len(s) == 1:
		return strings.ToUpper(s)
	default:
		return strings.ToUpper(string(s[0])) + s[1:]
	}
}
