package auth

import (
	"encoding/base64"
	"github.com/gin-gonic/gin"
	"net/http"
	"regexp"
	"strings"
)

type Handler interface {
	AddLoginEndpoint(route gin.IRouter, relativePath string)
	AddTokenEndpoint(route gin.IRouter, relativePath string)
	AddRefreshEndpoint(route gin.IRouter, relativePath string)
	AddAuthProtocol(route gin.IRouter, middleware func(ctx *gin.Context))
}

type handler struct {
	authService authorizationService
}

func DefaultAuthHandler(usrPwd Authorizer, clientCred Authorizer, signer TokenSigner, scopes ScopeProvider) Handler {
	authorizers := map[string]Authorizer{PasswordCredentials: usrPwd, ClientCredentials: clientCred}
	return NewAuthHandler(authorizers, signer, scopes)
}

func NewAuthHandler(authorizers map[string]Authorizer, signer TokenSigner, scopes ScopeProvider) Handler {
	return &handler{authorizationService{authorizers, signer, scopes}}
}

type userData []string

func (ud userData) getName() string {
	return ud[0]
}

func (ud userData) getPassword() string {
	return ud[1]
}

func getCredentials(credentials string) userData {
	return strings.Split(credentials, ":")
}

func (ah handler) AddAuthProtocol(route gin.IRouter, middleware func(ctx *gin.Context)) {
	route.POST("/login", ah.authorize)

	tknGroup := route.Group("/token")
	tknGroup.Use(middleware)
	tknGroup.GET("", WithScopes(ah.refreshToken, []string{RefreshTokenScope}))

	accessTknGroup := route.Group("/refresh")
	accessTknGroup.Use(middleware)
	accessTknGroup.GET("", WithScopes(ah.accessToken, []string{RefreshTokenScope}))
}

func (ah handler) AddLoginEndpoint(route gin.IRouter, relativePath string) {
	route.POST(relativePath, ah.authorize)
}

func (ah handler) AddTokenEndpoint(route gin.IRouter, relativePath string) {
	route.GET(relativePath, WithScopes(ah.accessToken, []string{RefreshTokenScope}))
}

func (ah handler) AddRefreshEndpoint(route gin.IRouter, relativePath string) {
	route.GET(relativePath, WithScopes(ah.refreshToken, []string{RefreshTokenScope}))
}

func (ah handler) authorize(ctx *gin.Context) {
	grantType := ctx.Request.Header.Get(GrantTypeHeader)
	authHeader := strings.Trim(ctx.Request.Header.Get(AuthorizationHeader), " ")
	tknRegex := regexp.MustCompile(`(?i)basic (.*)`)

	if !tknRegex.MatchString(authHeader) {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized,
			gin.H{"error": "unable to authenticate request. Invalid 'Authorization' header2"})
		return
	}

	userHash := tknRegex.FindAllStringSubmatch(authHeader, -1)[0][1]
	decodedUserHash, err := base64.StdEncoding.DecodeString(userHash)

	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	credentials := getCredentials(string(decodedUserHash))
	token, err := ah.authService.Authorize(UserCredentials{
		Id:       credentials.getName(),
		Password: credentials.getPassword(),
		Grant:    strings.ToLower(grantType)})

	if err != nil {
		switch err.(type) {
		case InvalidGrant, InvalidUser:
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
			return
		default:
			ctx.JSON(http.StatusServiceUnavailable, gin.H{"error": "Server error"})
			return
		}
	}

	ctx.JSON(http.StatusOK, token)
}

func (ah handler) accessToken(ctx *gin.Context) {
	r, exists := ctx.Get(ReqAuthData)

	if !exists {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid grants"})
		return
	}

	sender := r.(RequestAuthData).Sender
	grantType := r.(RequestAuthData).GrantType

	token, err := ah.authService.AccessToken(UserCredentials{sender, "", grantType})

	if err != nil {
		switch err.(type) {
		case InvalidGrant, InvalidUser:
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
			return
		default:
			ctx.JSON(http.StatusServiceUnavailable, gin.H{"error": "Server error"})
			return
		}
	}

	ctx.JSON(http.StatusOK, gin.H{"access_token": token})
}

func (ah handler) refreshToken(ctx *gin.Context) {
	r, exists := ctx.Get(ReqAuthData)

	if !exists {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid grants"})
		return
	}

	sender := r.(RequestAuthData).Sender
	grantType := r.(RequestAuthData).GrantType

	credentials, err := ah.authService.Refresh(UserCredentials{sender, "", grantType})

	if err != nil {
		switch err.(type) {
		case InvalidGrant, InvalidUser:
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
			return
		default:
			ctx.JSON(http.StatusServiceUnavailable, gin.H{"error": "Server error"})
			return
		}
	}
	ctx.JSON(http.StatusOK, credentials)
}

func WithScopes(handler gin.HandlerFunc, scopes []string) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		r, exists := ctx.Get(ReqAuthData)
		if !exists {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid grants"})
			return
		}

		userScopes := r.(RequestAuthData).Scopes
		if checkScopes(userScopes, scopes) {
			handler(ctx)
			return
		}

		ctx.JSON(http.StatusForbidden, gin.H{"error": "Forbidden, no valid grant"})
		return
	}
}

func checkScopes(firstArray []string, secondArray []string) bool {
	for _, s := range firstArray {
		for _, is := range secondArray {
			if s == is {
				return true
			}
		}
	}
	return false
}
