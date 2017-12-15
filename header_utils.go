package jwt

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const IndividualHeaderPrefix = "Token-Claim-"
const SingleHeader = "Token-Claims"

func NewHeaderUtilImpl() HeaderUtil {
	return &HeaderUtilImpl{}
}

type HeaderUtilImpl struct {
}

func (h *HeaderUtilImpl) stripSpoofHeaders(r *http.Request) {
	// strip potentially spoofed claims
	for header := range r.Header {
		if strings.HasPrefix(header, IndividualHeaderPrefix) || header == SingleHeader {
			r.Header.Del(header)
		}
	}
}

func (h *HeaderUtilImpl) setClaimHeaders(r *http.Request, rule Rule, vClaims map[string]interface{}, uToken string) {
	// set claims as separate headers for downstream to consume
	if rule.IndividualClaimHeaders {
		for header, value := range getIndividualClaimHeaders(rule, vClaims) {
			r.Header.Set(header, value)
		}
	}
	if rule.SingleClaimHeader {
		r.Header.Set(SingleHeader, getSingleClaimHeaders(uToken))
	}
}

func getIndividualClaimHeaders(rule Rule, vClaims map[string]interface{}) map[string]string {
	headers := make(map[string]string)
	for claim, value := range vClaims {
		var headerName string
		switch rule.StripHeader {
		case true:
			stripped := strings.SplitAfter(claim, "/")
			finalStrip := stripped[len(stripped)-1]
			headerName = IndividualHeaderPrefix + modTitleCase(finalStrip)
		default:
			escaped := url.PathEscape(claim)
			headerName = IndividualHeaderPrefix + modTitleCase(escaped)
		}

		switch v := value.(type) {
		case string:
			headers[headerName] = v
		case int64:
			headers[headerName] = strconv.FormatInt(v, 10)
		case bool:
			headers[headerName] = strconv.FormatBool(v)
		case int32:
			headers[headerName] = strconv.FormatInt(int64(v), 10)
		case float32:
			headers[headerName] = strconv.FormatFloat(float64(v), 'f', -1, 32)
		case float64:
			headers[headerName] = strconv.FormatFloat(v, 'f', -1, 64)
		case []interface{}:
			b := bytes.NewBufferString("")
			for i, item := range v {
				if i > 0 {
					b.WriteString(",")
				}
				b.WriteString(fmt.Sprintf("%v", item))
			}
			headers[headerName] = b.String()
		default:
			// ignore, because, JWT spec says in https://tools.ietf.org/html/rfc7519#section-4
			//     all claims that are not understood
			//     by implementations MUST be ignored.
		}
	}
	return headers
}

func getSingleClaimHeaders(uToken string) string {
	return strings.Split(uToken, ".")[1]
}
