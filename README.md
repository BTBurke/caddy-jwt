## JWT

[![Build Status](https://travis-ci.org/BTBurke/caddy-jwt.svg?branch=master)](https://travis-ci.org/BTBurke/caddy-jwt)

**Authorization Middleware for Caddy**

This middleware implements an authorization layer for [Caddy](https://caddyserver.com) based on JSON Web Tokens (JWT).  You can learn more about using JWT in your application at [jwt.io](https://jwt.io).

### Basic Syntax

```
jwt [path]
```

By default every resource under path will be secured using JWT validation.  To specify a list of resources that need to be secured, use multiple declarations:

```
jwt [path1]
jwt [path2]
```

> **Important** You must set the secret used to construct your token in an environment variable named `JWT_SECRET`(HMAC) *or* `JWT_PUBLIC_KEY`(RSA or ECDSA).  Otherwise, your tokens will silently fail validation.  Caddy will start without this value set, but it must be present at the time of the request for the signature to be validated.

### Advanced Syntax

You can optionally use claim information to further control access to your routes.  In a `jwt` block you can specify rules to allow or deny access based on the value of a claim.
If the claim is a json array of strings, the allow and deny directives will check if the array contains the specified string value.  An allow or deny rule will be valid if any value in the array is a match.

```
jwt {
   path [path]
   redirect [location]
   redirectcode [code]
   allow [claim] [value]
   deny [claim] [value]
}
```

To authorize access based on a claim, use the `allow` syntax.  To deny access, use the `deny` keyword.  You can use multiple keywords to achieve complex access rules.  If any `allow` access rule returns true, access will be allowed.  If a `deny` rule is true, access will be denied.  Deny rules will allow any other value for that claim.   

  For example, suppose you have a token with `user: someone` and `role: member`.  If you have the following access block:

```
jwt {
   path /protected
   deny role member
   allow user someone
}
```

The middleware will deny everyone with `role: member` but will allow the specific user named `someone`.  A different user with a `role: admin` or `role: foo` would be allowed because the deny rule will allow anyone that doesn't have role member.

If the optional `redirect` is set, the middleware will send a redirect to the supplied location (HTTP 303) instead of an access denied code, if the access is denied.

If the optional `redirectcode` is set, the middleware will use the supplied code instead of HTTP 303

### Ways of passing a token for validation

There are three ways to pass the token for validation: (1) in the `Authorization` header, (2) as a cookie, and (3) as a URL query parameter.  The middleware will **by default** look in those places in the order listed and return `401` if it can't find any token.

| Method               | Format                          |
| -------------------- | ------------------------------- |
| Authorization Header | `Authorization: Bearer <token>` |
| Cookie               | `"jwt_token": <token>`          |
| URL Query Parameter  | `/protected?token=<token>`      |

It is possible to customize what token sources should be used via the `token_source` rule. If at one or more `token_source` rules are specified, they will be used instead of the default in the given order. For example, to
do the same validation as default, but with the different header, cookie and query param names, the user could use the following snippet:

```
jwt {
   ...
   token_source header my_header_type
   token_source cookie my_cookie_name
   token_source query_param my_param_name
}
```

#### Note about `Authorization` header

The optional header type is for Bearer tokens by other names, like `ApplePass` used by Apple PassKit. If not provided, it defaults to `Bearer` as defined in RFC6750. This does not support more complex schemes that require a challenge/response.

### Constructing a valid token

JWTs consist of three parts: header, claims, and signature.  To properly construct a JWT, it's recommended that you use a JWT library appropriate for your language.  At a minimum, this authorization middleware expects the following fields to be present:

##### Header

```json
{
"typ": "JWT",
"alg": "HS256|HS384|HS512|RS256|RS384|RS512|ES256|ES384|ES512"
}
```

##### Claims

If you want to limit the validity of your tokens to a certain time period, use the "exp" field to declare the expiry time of your token.  This time should be a Unix timestamp in integer format.
```json
{
"exp": 1460192076
}
```

### Acting on claims in the token

You can of course add extra claims in the claim section.  Once the token is validated, the claims you include will be passed as headers to a downstream resource.  Since the token has been validated by Caddy, you can be assured that these headers represent valid claims from your token.  For example, if you include the following claims in your token:

```json
{
  "user": "test",
  "role": "admin",
  "logins": 10,
  "groups": ["user", "operator"],
  "data": {
    "payload": "something"
  }
}
```

The following headers will be added to the request that is proxied to your application:

```
Token-Claim-User: test
Token-Claim-Role: admin
Token-Claim-Logins: 10
Token-Claim-Groups: user,operator
Token-Claim-Data.payload: something
```

Token claims will always be converted to a string.  If you expect your claim to be another type, remember to convert it back before you use it.  Nested JSON objects will be flattened.  In the example above, you can see that the nested `payload` field is flattened to `data.payload`.

All request headers with the prefix `Token-Claim-` are stripped from the request before being forwarded upstream, so users can't spoof them.

Claims with special characters that aren't allowed in HTTP headers will be URL escaped.  For example, Auth0 requires that claims be namespaced with the full URL such as

```json
{
  "http://example.com/user": "test"
}
```

The URL escaping will lead to some ugly headers like

```
Token-Claim-Http:%2F%2Fexample.com%2Fuser: test
```

If you only care about the last section of the path, you can use the `strip_header` directive to strip everything before the last portion of the path.

```
jwt {
  path /
  strip_header
}
```

When combined with the claims above, it will result in a header:

```
Token-Claim-User: test
```

### Allowing Public Access to Certain Paths

In some cases, you may want to allow public access to a particular path without a valid token.  For example, you may want to protect all your routes except access to the `/login` path.  You can do that with the `except` directive.

```
jwt {
  path /
  except /login
}
```

Every path that begins with `/login` will be excepted from the JWT token requirement.  All other paths will be protected.  In the case that you set your path to the root as in the example above, you also might want to allow access to the so-called naked or root domain while protecting everything else.  You can use the directive `allowroot` which will allow access to the naked domain.  For example, if you have the following config block:

```
jwt {
  path /
  except /login
  allowroot
}
```

Requests to `https://example.com/login` and `https://example.com/` will both be allowed without a valid token.  Any other path will require a valid token.

### Allowing Public Access Regardless of Token

In some cases, a page should be accessible whether a valid token is present or not. An example might be the Github home page or a public repository, which should be visible even to logged-out users. In those cases, you would want to parse any valid token that might be present and pass the claims through to the application, leaving it to the application to decide whether the user has access. You can use the directive `passthrough` for this:

```
jwt {
  path /
  passthrough
}
```

It should be noted that `passthrough` will *always* allow access on the path provided, regardless of whether a token is present or valid, and regardless of `allow`/`deny` directives. The application would be responsible for acting on the parsed claims.

### Specifying Keys for Use in Validating Tokens

There are two ways to specify key material used in validating tokens.  If you run Caddy in a container or via an init system like Systemd, you can directly specify your keys using the environment variables `JWT_SECRET` for HMAC or `JWT_PUBLIC_KEY` for RSA or ECDSA (PEM-encoded public key).  You cannot use both at the same time because it would open up a known security hole in the JWT specification.  When you run multiple sites, all would have to use the same keys to validate tokens.

When you run multiple sites from one Caddyfile, you can specify the location of a file that contains your PEM-encoded public key or your HMAC secret.  Once again, you cannot use both for the same site because it would cause a security hole.  However, you can use different methods on different sites because the configurations are independent.

For RSA or ECDSA tokens:

```
jwt {
  path /
  publickey /path/to/key.pem
} 
```

For HMAC:

```
jwt {
  path /
  secret /path/to/secret.txt
}
```

When you store your key material in a file, this middleware will cache the result and use the modification time on the file to determine if the secret has changed since the last request.  This should allow you to rotate your keys or invalidate tokens by writing a new key to the file without worrying about possible file locking problems (although you should still check that your write succeeded before issuing tokens with your new key.)

If you have multiple public keys or secrets that should be considered valid, use multiple declarations to the keys or secrets in different files.  Authorization will be allowed if any of the keys validate the token.

```
jwt {
  path /
  publickey /path/to/key1.pem
  publickey /path/to/key2.pem
}
```

### Possible Return Status Codes

| Code | Reason |
| ---- | ------ |
| 401 | Unauthorized - no token, token failed validation, token is expired |
| 403 | Forbidden - Token is valid but denied because of an ALLOW or DENY rule |
| 303 | A 401 or 403 was returned and the redirect is enabled.  This takes precedence over a 401 or 403 status. |


### Caveats

JWT validation depends only on validating the correct signature and that the token is unexpired.  You can also set the `nbf` field to prevent validation before a certain timestamp.  Other fields in the specification, such as `aud`, `iss`, `sub`, `iat`, and `jti` will not affect the validation step.
