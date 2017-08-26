# v3.0.0

The major feature is support for Auth0-style claims which require a fully namespaced key.  This leads to claims that look like

```json
{
    "http://example.com/user": "test"
}
```

This creates problems for passing the claims as a header value because of characters such as `/` which are not allowed.

## Breaking changes

* `Token-Claim` headers are now URL escaped
* Token claim headers are passed as title case to align with the docs and standard practice.  Prior to v3, tokens were all upper case despite being listed as title case in the docs.
* `strip_header` directive added to strip out the namespacing up to the last portion of the path.  This is primarily useful for constructing nicer-looking header values for Auth0 tokens.

# v2.6.0

This release adds the ability to specify multiple public keys or secrets that may be used to validate tokens.  The primary use case is for JWTs that may be issued by multiple authorities.  All keys configured in the Caddyfile will be tried for each request.  Access will be authorized if any key validates the token.