# <img src="https://github.com/bryst/windmill/blob/master/.github/windmill.png" height="35"/>WINDMILL

![Go](https://github.com/bryst/windmill/workflows/Go/badge.svg?branch=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/bryst/windmill)](https://goreportcard.com/report/github.com/bryst/windmill)
[![](https://godoc.org/github.com/tendermint/iavl?status.svg)](https://pkg.go.dev/github.com/bryst/windmill)

```text
... Putting a number of small windmills throughout your orchard can scare off the birds ...
```

## What is it?

This is a small library to implement token based [authentication](https://tools.ietf.org/html/rfc6749#page-11)

We provide abstractions to implement both the auth server flows and the resource server token validation.

This includes an "out of the box" implementations for both parts using [gin](https://github.com/gin-gonic/gin) framework.

It is possible to use the the [TokenServer](https://github.com/bryst/windmill/blob/master/pkg/auth/auth.go#L47) abstraction to implement the auth server using any other routing framework.

In the future we might provide out of the box implementations for other frameworks.

## Implementing an Auth-Server

You will need to provide a few implementations in order to leverage the token flow provided by this lib.
```
type Authorizer func(uc Credentials) error
```
This is used to authenticate the user based on the credentials provided by the sender. Credentials exchange is done using the [Basic Authentication Scheme](https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication#Basic_authentication_scheme).

In addition to the `Authorization` header you will need to provide a `GRANT-TYPE` header. You migh define your own `Grant-Type`, as defaults we provide two options:

* `password_credentials` : Intended to be used to authenticate users
* `client_credentials` : Ingended to be used in a machine to machine scenario.

You Will need to provide an `Authorizer` for each `GRANT-TYPE`. 

```
type ScopeProvider func(userId string, grant string, aud string, requested Scopes) (Scopes, error)
```
This retrieves, from the requested scopes, the ones that are actually granted for the user and audience combo.

```
type UserAudValidator func(userId string, grant string, aud string) (bool, error)
```
This is used to check if the given user+grant is register to access the resource (aud)

```
type ClaimProvider func(identifier string, aud string) ([]Claim, error)
```
Retrieves a list of custom Claims you might want to add to the default claims.

### Gin

To register the endpoints necessary to run an auth server using gin just call

```
    ginAuth, err := auth.BasicGinAuth(&auth.GinAuthConfig{
            UsrAuthorizer:     ..., // Users Authorizer
            ClientAuthorizer:  ..., // M2M Authorizer
            ScopeProvider:     ...
            AudValidator:      ...
            ClaimProvider:      ...
            SigningKey:         ...
            AccessTknDuration:  ...
            RefreshTknDuration: ...
            AppId:              ..})

	if err != nil {
		log.Fatal(err)
	}

    router := gin.New()
    api := router.Group("/api")
    v1 := api.Group("/v1")
    ginAuth.AddAuthProtocol(v1, auth.NewAuthServerMiddleware())
```

This will add 4 endpoints:

##### `/authorize` 

GET to authenticate an user. As optional query parameters you can pass :

* `scope` coma separated list of scopes you want for the user
* `aud` the final resource server id that will read the access token. If none is provided the default value is the auth-server id.

You must include the `Authentication` and `GRANT-TYPE` headers

###### Response
```json
{
    "access_token": "...",
    "refresh_token": "..."
}
```

##### `/token` 

GET - Retrieves a new pair of `access_token` and `refresh_token`. As additional query params it takes:

* `scope` coma separated list of scopes you want for the user

You must include the `Authentication` with  [bearer](https://tools.ietf.org/html/rfc6750) data. 

###### Response
```json
{
    "access_token": "...",
    "refresh_token": "..."
}
```

##### `/refresh` 

GET - Retrieves a new  `access_token` only. As additional query params it takes:

* `scope` coma separated list of scopes you want for the user

You must include the `Authentication` with  [bearer](https://tools.ietf.org/html/rfc6750) data. 

###### Response
```json
{
    "access_token": "...",
}
```

##### `/public_key` 

GET - Retrieves the public key of teh signing key used to sign the tokens. The public key exposed is a pem encoded string.

###### Response
```text
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAErkDz1UwxL/Xbq7s77BsQSUfS5pI8
7NaQmJoJIBtnzY+3NcD8Jc6TyTRG92eGcYk1Drm6+/NaOrih28239zhvNA==
-----END PUBLIC KEY-----
```
#### Alternative usages

You can register only the endoints you want by calling specific functions for each method.

Also, if you want to provide another `Authenticator` configuration, instead of calling `BasicGinAuth` you can call

```
func NewGinAuth(authorizers map[string]Authorizer, clProv ClaimProvider,
	signer TokenSigner, scopes ScopeProvider, clients UserAudValidator) (GinAuth, error) {
```
#### Example

Very basic Auth-Server [example](https://github.com/bryst/windmill/blob/master/examples/gin/auth-server/main.go#L14)

### Gin - Resource Server

You would just need to add a middleware to validate the `access_token` and declare the required scopes to access a given path.

```
route.Use(auth.NewBasicMiddleware(func() *ecdsa.PublicKey {
		pub, err := keys.ReadRemotePublicKey("http://localhost:8080/api/v1/public_key")
		if err != nil {
			log.Fatal(err)
		}
		return pub
	}, "API1"))

route.GET("/hello", auth.WithScopes(func(context *gin.Context) {
		context.JSON(http.StatusOK, gin.H{"health": "Hello there common user!"})
	}, "read:api"))
```
The `NewBasicMiddleware` function receives a function to retrieve the public key associated with the signing key of the token. Also, it takes the external id of your resource server.

If you want to add your own validations for the claims in the token, you can use

```
   func NewAuthMiddleware(pubKey func() *ecdsa.PublicKey, validations ...ClaimValidation) func(ctx *gin.Context) {
```

That function receives as many `ClaimValidation` as you want.

#### Example

Very basic Resourece-Server [example](https://github.com/bryst/windmill/blob/master/examples/gin/resource-server/main.go#L14)
