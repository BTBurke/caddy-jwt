package jwt

import (
	"fmt"
	"github.com/mholt/caddy/caddy/setup"
	"github.com/mholt/caddy/middleware"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"net/http"
	"testing"
)

func TestCaddyJwtConfig(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "CaddyJWT Config Suite")
}

var EmptyNext = middleware.HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
	return 0, nil
})

var _ = Describe("JWTAuth Config", func() {
	Describe("Parse the jwt config block", func() {

		It("parses a simple declaration", func() {
			c := setup.NewTestController(`jwt /from`)

			mid, err := Setup(c)
			Expect(err).To(BeNil())

			handler := mid(EmptyNext)
			_, ok := handler.(*JWTAuth)
			if !ok {
				Fail(fmt.Sprintf("wrong type for handler: %#v", handler))
			}

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
			}
			for _, test := range tests {
				c := setup.NewTestController(test.input)
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
