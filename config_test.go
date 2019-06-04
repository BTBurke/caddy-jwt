package jwt

import (
	"net/http"
	"testing"

	"fmt"
	"os"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestCaddyJwtConfig(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "CaddyJWT Config Suite")
}

var EmptyNext = httpserver.HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
	return 0, nil
})

var _ = Describe("JWTAuth Config", func() {
	BeforeEach(func() {
		os.Unsetenv(ENV_PUBLIC_KEY)
		os.Unsetenv(ENV_SECRET)
	})
	Describe("Parse the jwt config block", func() {

		It("returns an appropriate middleware handler", func() {
			c := caddy.NewTestController("http", `jwt /from`)
			err := Setup(c)
			Expect(err).To(BeNil())
		})

		It("parses simple and complex blocks", func() {
			tests := []struct {
				input     string
				shouldErr bool
				expect    []Rule
			}{
				{"jwt /test", false, []Rule{{Path: "/test"}}},
				{"jwt {\npath /test\n}", false, []Rule{{Path: "/test"}}},
				{`jwt {
					path /test
                                        redirect /login
					allow user test
				}`, false, []Rule{{
					Path:        "/test",
					Redirect:    "/login",
					AccessRules: []AccessRule{{ALLOW, "user", "test"}}},
				}},
				{`jwt /test {
					allow user test
				}`, true, nil},
				{`jwt {
					path /test
					deny role member
					allow user test
				}`, false, []Rule{{Path: "/test", AccessRules: []AccessRule{{DENY, "role", "member"}, {ALLOW, "user", "test"}}}}},
				{`jwt {
					deny role member
				}`, true, nil},
				{`jwt /path1
				jwt /path2`, false, []Rule{{Path: "/path1"}, {Path: "/path2"}}},
				{`jwt {
					path /path1
					path /path2
				}`, true, nil},
				{`jwt {
					path /
					except /login
					except /test
					allowroot
				}`, false, []Rule{
					Rule{
						Path:          "/",
						ExceptedPaths: []string{"/login", "/test"},
						AllowRoot:     true,
					},
				}},
				{`jwt {
					path /
					publickey /test/test.pem
				}`, false, []Rule{
					Rule{
						Path:        "/",
						KeyBackends: []KeyBackend{&LazyPublicKeyBackend{filename: "/test/test.pem"}},
					},
				}},
				{`jwt {
					path /
					secret /test/test.secret
				}`, false, []Rule{
					Rule{
						Path:        "/",
						KeyBackends: []KeyBackend{&LazyHmacKeyBackend{filename: "/test/test.secret"}},
					},
				}},
				{`jwt {
					path /
					secret /test/test.secret
					secret /test/test2.secret
				}`, false, []Rule{
					Rule{
						Path:        "/",
						KeyBackends: []KeyBackend{&LazyHmacKeyBackend{filename: "/test/test.secret"}, &LazyHmacKeyBackend{filename: "/test/test2.secret"}},
					},
				}},
				{`jwt {
					path /
					publickey /test/test.pub
					publickey /test/test2.pub
				}`, false, []Rule{
					Rule{
						Path:        "/",
						KeyBackends: []KeyBackend{&LazyPublicKeyBackend{filename: "/test/test.pub"}, &LazyPublicKeyBackend{filename: "/test/test2.pub"}},
					},
				}},
				{`jwt {
					path /
					publickey /test/test.pub
					secret /test/test.secret
				}`, true, nil},
				{`jwt {
					path /
					passthrough
				}`, false, []Rule{
					Rule{
						Path:        "/",
						Passthrough: true,
					},
				}},
				{`jwt {
					path /
					token_source
				}`, true, nil,
				},
				{`jwt {
					path /
					token_source unexpected
				}`, true, nil,
				},
				{`jwt {
					path /
					token_source header foo bar
				}`, true, nil,
				},
				{`jwt {
					path /
					token_source query_param
				}`, true, nil,
				},
				{`jwt {
					path /
					token_source cookie
				}`, true, nil,
				},
				{`jwt {
					path /
					token_source query_param param_name
					token_source cookie cookie_name
					token_source header header_name
					token_source header
				}`, false, []Rule{
					Rule{
						Path: "/",
						TokenSources: []TokenSource{
							&QueryTokenSource{
								ParamName: "param_name",
							},
							&CookieTokenSource{
								CookieName: "cookie_name",
							},
							&HeaderTokenSource{
								HeaderName: "header_name",
							},
							&HeaderTokenSource{
								HeaderName: "Bearer",
							},
						},
					},
				}},
			}
			for _, test := range tests {
				c := caddy.NewTestController("http", test.input)
				actual, err := parse(c)
				if !test.shouldErr {
					Expect(err).To(BeNil())
				} else {
					Expect(err).To(HaveOccurred(), fmt.Sprintf("%v", test))
				}
				for idx, rule := range test.expect {
					actualRule := actual[idx]
					Expect(rule.Path).To(Equal(actualRule.Path))
					Expect(rule.Redirect).To(Equal(actualRule.Redirect))
					Expect(rule.AccessRules).To(Equal(actualRule.AccessRules))
					Expect(rule.ExceptedPaths).To(Equal(actualRule.ExceptedPaths))
					Expect(rule.AllowRoot).To(Equal(actualRule.AllowRoot))
					Expect(rule.KeyBackends).To(Equal(actualRule.KeyBackends), fmt.Sprintf("expected: %v\nactual: %v", rule, actualRule))
					Expect(rule.TokenSources).To(Equal(actualRule.TokenSources), fmt.Sprintf("expected: %v\nactual: %v", rule, actualRule))
				}

			}
		})

	})
})
