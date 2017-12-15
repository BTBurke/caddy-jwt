package jwt

import (
	"net/http"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("HeaderUtil", func() {

	headerUtils := NewHeaderUtilImpl()

	vClaims := make(map[string]interface{})
	vClaims["user"] = "test"
	vClaims["bool"] = true
	vClaims["float32"] = float32(3.14159)
	vClaims["float64"] = float64(3.14159)
	vClaims["int32"] = int32(10)
	list := make([]interface{}, 3)
	list[0] = "foo"
	list[1] = "bar"
	list[2] = "bazz"
	vClaims["list"] = list
	vClaims["http://test.com/path"] = "true"

	expectedIndividualHeaders := map[string]string{
		"Token-Claim-User":                       "test",
		"Token-Claim-Bool":                       "true",
		"Token-Claim-Float32":                    "3.14159",
		"Token-Claim-Float64":                    "3.14159",
		"Token-Claim-Int32":                      "10",
		"Token-Claim-List":                       "foo,bar,bazz",
		"Token-Claim-Http:%2F%2Ftest.com%2Fpath": "true",
	}

	uToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"
	uTokenClaims := "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9"

	It("set claims as individual headers", func() {
		rule := Rule{IndividualClaimHeaders: true}
		req, _ := http.NewRequest("GET", "/testing", nil)

		headerUtils.setClaimHeaders(req, rule, vClaims, uToken)

		for head, value := range expectedIndividualHeaders {
			Expect(req.Header.Get(head)).To(Equal(value))
		}

		Expect(req.Header.Get("Token-Claims")).To(Equal(""))
	})

	It("set claim as single header", func() {
		rule := Rule{SingleClaimHeader: true}
		req, _ := http.NewRequest("GET", "/testing", nil)

		headerUtils.setClaimHeaders(req, rule, vClaims, uToken)

		expectedHeaders := map[string]string{
			"Token-Claim-User":                       "test",
			"Token-Claim-Bool":                       "true",
			"Token-Claim-Float32":                    "3.14159",
			"Token-Claim-Float64":                    "3.14159",
			"Token-Claim-Int32":                      "10",
			"Token-Claim-List":                       "foo,bar,bazz",
			"Token-Claim-Http:%2F%2Ftest.com%2Fpath": "true",
		}
		for head, _ := range expectedHeaders {
			Expect(req.Header.Get(head)).To(Equal(""))
		}
		Expect(req.Header.Get("Token-Claims")).To(Equal(uTokenClaims))
	})
})
