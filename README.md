## JWT

**Authorization Middleware for Caddy**

This middleware implements an authorization layer for [Caddy](https://caddyserver.com) based on JSON Web Tokens (JWT).  You can learn more about using JWT in your application at [jwt.io](https://jwt.io).

Build Status: [![CircleCI](https://circleci.com/gh/BTBurke/caddy-jwt/tree/master.svg?style=svg)](https://circleci.com/gh/BTBurke/caddy-jwt/tree/master)

### Basic Syntax

```
jwt [path]
```

By default every resource under path will be secured using JWT validation.  To specify a list of resources that need to be secured, use multiple declarations:

```
jwt [path1]
jwt [path2]
```

> **Important** You must set the secret used to construct your token in an environment variable named `JWT_SECRET`(HMAC) *or* `JWT_PUBLIC_KEY`(RSA).  Otherwise, your tokens will always silently fail validation.  Caddy will start without this value set, but it must be present at the time of the request for the signature to be validated.

### Advanced Syntax

You can optionally use claim information to further control access to your routes.  In a `jwt` block you can specify rules to allow or deny access based on the value of a claim.
If the claim is a json array of strings, the allow and deny directives will check if the array contains the specified string value.  An allow or deny rule will be valid if any value in the array is a match.

```
jwt {
   path [path]
   redirect [location]
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

### Ways of passing a token for validation

There are three ways to pass the token for validation: (1) in the `Authorization` header, (2) as a cookie, and (3) as a URL query parameter.  The middleware will look in those places in the order listed and return `401` if it can't find any token.

| Method               | Format                          |
| -------------------- | ------------------------------- |
| Authorization Header | `Authorization: Bearer <token>` |
| Cookie               | `"jwt_token": <token>`          |
| URL Query Parameter  | `/protected?token=<token>`      |

### Constructing a valid token

JWTs consist of three parts: header, claims, and signature.  To properly construct a JWT, it's recommended that you use a JWT library appropriate for your language.  At a minimum, this authorization middleware expects the following fields to be present:

##### Header

```json
{
"typ": "JWT",
"alg": "HS256|HS384|HS512|RS256|RS384|RS512"
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
Token-Claim-Data.Payload: something
```

Token claims will always be converted to a string.  If you expect your claim to be another type, remember to convert it back before you use it.  Nested JSON objects will be flattened.  In the example above, you can see that the nested `payload` field is flattened to `data.payload`.

### Caveats

JWT validation depends only on validating the correct signature and that the token is unexpired.  You can also set the `nbf` field to prevent validation before a certain timestamp.  Other fields in the specification, such as `aud`, `iss`, `sub`, `iat`, and `jti` will not affect the validation step.
