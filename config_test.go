package jwt

import (
	"net/http"
	"testing"

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
				{"jwt /test", false, []Rule{Rule{"/test", nil}}},
				{"jwt {\npath /test\n}", false, []Rule{Rule{"/test", nil}}},
				{`jwt {
					path /test
					allow user test
				}`, false, []Rule{Rule{"/test", []AccessRule{AccessRule{ALLOW, "user", "test"}}}}},
				{`jwt /test {
					allow user test
				}`, true, nil},
				{`jwt {
					path /test
					deny role member
					allow user test
				}`, false, []Rule{Rule{"/test", []AccessRule{AccessRule{DENY, "role", "member"}, AccessRule{ALLOW, "user", "test"}}}}},
				{`jwt {
					deny role member
				}`, true, nil},
				{`jwt /path1
				jwt /path2`, false, []Rule{Rule{"/path1", nil}, Rule{"/path2", nil}}},
				{`jwt {
					path /path1
					path /path2
				}`, true, nil},
			}
			for _, test := range tests {
				c := caddy.NewTestController("http", test.input)
				actual, err := parse(c)
				if !test.shouldErr {
					Expect(err).To(BeNil())
				} else {
					Expect(err).To(HaveOccurred())
				}
				for idx, rule := range test.expect {
					actualRule := actual[idx]
					Expect(rule.Path).To(Equal(actualRule.Path))
					Expect(rule.AccessRules).To(Equal(actualRule.AccessRules))
				}

			}
		})

	})
})
