package jwt

import (
	"fmt"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

// RuleType distinguishes between ALLOW and DENY rules
type RuleType int

const (
	// ALLOW represents a rule that should allow access based on claim value
	ALLOW RuleType = iota

	// DENY represents a rule that should deny access based on claim value
	DENY
)

// EncryptionType distinguishes between RSA and HMAC key material when stored in a file
type EncryptionType int

const (
	// RSA is used to specify a file that contains a PEM-encoded public key
	RSA EncryptionType = 1 << iota

	// HMAC is used to specify a file that contains a HMAC-SHA secret
	HMAC
)

// Auth represents configuration information for the middleware
type Auth struct {
	Rules []Rule
	Next  httpserver.Handler
	Realm string
}

// Rule represents the configuration for a site
type Rule struct {
	Path          string
	ExceptedPaths []string
	AccessRules   []AccessRule
	Redirect      string
	AllowRoot     bool
	KeyFile       string
	KeyFileType   EncryptionType
}

// AccessRule represents a single ALLOW/DENY rule based on the value of a claim in
// a validated token
type AccessRule struct {
	Authorize RuleType
	Claim     string
	Value     string
}

func init() {
	caddy.RegisterPlugin("jwt", caddy.Plugin{
		ServerType: "http",
		Action:     Setup,
	})
}

// Setup is called by Caddy to parse the config block
func Setup(c *caddy.Controller) error {
	rules, err := parse(c)
	if err != nil {
		return err
	}

	c.OnStartup(func() error {
		fmt.Println("JWT middleware is initiated")
		return nil
	})

	host := httpserver.GetConfig(c).Addr.Host

	httpserver.GetConfig(c).AddMiddleware(func(next httpserver.Handler) httpserver.Handler {
		return &Auth{
			Rules: rules,
			Next:  next,
			Realm: host,
		}
	})

	return nil
}

func parse(c *caddy.Controller) ([]Rule, error) {
	// This parses the following config blocks
	/*
		jwt /hello
		jwt /anotherpath
		jwt {
			path /hello
		}
	*/
	var rules []Rule
	for c.Next() {
		args := c.RemainingArgs()
		switch len(args) {
		case 0:
			// no argument passed, check the config block

			var r = Rule{}
			for c.NextBlock() {
				switch c.Val() {
				case "path":
					if !c.NextArg() {
						// we are expecting a value
						return nil, c.ArgErr()
					}
					// return error if multiple paths in a block
					if len(r.Path) != 0 {
						return nil, c.ArgErr()
					}
					r.Path = c.Val()
					if c.NextArg() {
						// we are expecting only one value.
						return nil, c.ArgErr()
					}
				case "except":
					if !c.NextArg() {
						return nil, c.ArgErr()
					}
					r.ExceptedPaths = append(r.ExceptedPaths, c.Val())
					if c.NextArg() {
						// except only allows one path per declaration
						return nil, c.ArgErr()
					}
				case "allowroot":
					r.AllowRoot = true
				case "allow":
					args1 := c.RemainingArgs()
					if len(args1) != 2 {
						return nil, c.ArgErr()
					}
					r.AccessRules = append(r.AccessRules, AccessRule{Authorize: ALLOW, Claim: args1[0], Value: args1[1]})
				case "deny":
					args1 := c.RemainingArgs()
					if len(args1) != 2 {
						return nil, c.ArgErr()
					}
					r.AccessRules = append(r.AccessRules, AccessRule{Authorize: DENY, Claim: args1[0], Value: args1[1]})
				case "redirect":
					args1 := c.RemainingArgs()
					if len(args1) != 1 {
						return nil, c.ArgErr()
					}
					r.Redirect = args1[0]
				case "publickey":
					args1 := c.RemainingArgs()
					if len(args1) != 1 || r.KeyFileType != 0 {
						return nil, c.ArgErr()
					}
					r.KeyFile = args1[0]
					r.KeyFileType = RSA
				case "secret":
					args1 := c.RemainingArgs()
					if len(args1) != 1 || r.KeyFileType != 0 {
						return nil, c.ArgErr()
					}
					r.KeyFile = args1[0]
					r.KeyFileType = HMAC
				}
			}
			rules = append(rules, r)
		case 1:
			rules = append(rules, Rule{Path: args[0]})
			// one argument passed
			if c.NextBlock() {
				// path specified, no block required.
				return nil, c.ArgErr()
			}
		default:
			// we want only one argument max
			return nil, c.ArgErr()
		}
	}
	// check all rules at least have a path
	for _, r := range rules {
		if r.Path == "" {
			return nil, fmt.Errorf("Each rule must have a path")
		}
	}
	return rules, nil
}
