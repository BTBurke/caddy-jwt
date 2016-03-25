## JWT

** Authorization Middleware for Caddy **

This middleware implements an authorization middleware for [Caddy](https://caddyserver.com) based on JSON Web Tokens (JWT).  You can learn more about using JWT in your application at [jwt.io](https://jwt.io).

### Syntax


```
jwt [path]
```

By default every resource under path will be secured using JWT validation.  To specify a list of resources that need to be secured, use:

```
jwt {
path [path1]
path [path2]
}
```

> **Important** You must set the secret used to construct your token in an environment variable named `JWT_SECRET`.  Otherwise, your tokens will always silently fail validation.  Caddy will start without this value set, but it must be present at the time of the request for the signature to be validated. 


### Constructing a valid token

JWTs consist of three parts: header, claims, and signature.  To properly construct a JWT, it's recommended that you use a JWT library appropriate for your language.  At a minimum, this authorization middleware expects the following fields to be present:

#### Header
```json
{
"typ": "JWT",
"alg": "<any supported algorithm except none>"
}
```

### Claims
```json
{
"exp": "<expiration date as a Unix timestamp>"
}
```

### Acting on claims in the token

You can of course add extra claims in the claim section.  Once the token is validated, the claims you include will be passed as headers to a downstream resource.  For example, if you include the following claims in your token:

```json
{
"user": "test",
"role: "admin",
"logins": 10
}
```

The following headers will be added to the request that is proxied to your application:

```
X-Token-Claim-User: test
X-Token-Claim-Role: admin
X-Token-Claim-Logins: 10
X-Token: <full token string>
```

Tokens will always be converted to a string.  If you pass another type in your claims, remember to convert it before you use it.  The full token string is always passed as `X-Token`.

### Caveats

JWT validation depends only on validating the correct signature and that the token is unexpired.  You can also set the `nbf` field to prevent validation before a certain timestamp.  Other fields in the specification, such as `aud`, `iss`, `sub`, `iat`, and `jti` will not affect the validation step.
