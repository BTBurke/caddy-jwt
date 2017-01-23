package jwt

import (
	"fmt"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

const (
	ALLOW = iota
	DENY
)

type JWTAuth struct {
	Rules []Rule
	Next  httpserver.Handler
}

type Rule struct {
	Path        string
	AccessRules []AccessRule
	Redirect    string
}

type AccessRule struct {
	Authorize int
	Claim     string
	Value     string
}

func init() {
	caddy.RegisterPlugin("jwt", caddy.Plugin{
		ServerType: "http",
		Action:     Setup,
	})
}

func Setup(c *caddy.Controller) error {
	rules, err := parse(c)
	if err != nil {
		return err
	}

	c.OnStartup(func() error {
		fmt.Println("JWT middleware is initiated")
		return nil
	})

	httpserver.GetConfig(c).AddMiddleware(func(next httpserver.Handler) httpserver.Handler {
		return &JWTAuth{
			Rules: rules,
			Next:  next,
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
			path /anotherpath
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
