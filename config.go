package jwt

import (
	"fmt"
	"github.com/mholt/caddy/caddy/setup"
	"github.com/mholt/caddy/middleware"
)

const (
	ALLOW = iota
	DENY
)

type JWTAuth struct {
	Rules []Rule
	Next  middleware.Handler
}

type Rule struct {
	Path        string
	AccessRules []AccessRule
}

type AccessRule struct {
	Authorize int
	Claim     string
	Value     string
}

func Setup(c *setup.Controller) (middleware.Middleware, error) {
	rules, err := parse(c)
	if err != nil {
		return nil, err
	}

	c.Startup = append(c.Startup, func() error {
		fmt.Println("JWT middleware is initiated")
		return nil
	})

	return func(next middleware.Handler) middleware.Handler {
		return &JWTAuth{
			Rules: rules,
			Next:  next,
		}
	}, nil
}

func parse(c *setup.Controller) ([]Rule, error) {
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
