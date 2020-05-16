package integration

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/healthyorchards/windmill/pkg/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type testRouter struct {
	*gin.Engine
	T *testing.T
}

type demoUser struct {
	Name     string
	Password string
	Scopes   string
}

type inMemoryData struct {
	users map[string]demoUser
}

func (id inMemoryData) authorizeHumanUser(uc auth.UserCredentials) error {
	u, ok := id.users[uc.Id]
	if !ok || uc.Password != u.Password {
		return auth.InvalidUser(errors.New("i dont know this person"))
	}
	return nil
}

func (id inMemoryData) authorizeMachineUser(_ auth.UserCredentials) error {
	return nil
}

func (id inMemoryData) getScopes(uc auth.UserCredentials) (auth.Scopes, error) {
	if uc.Grant == auth.ClientCredentials {
		return "admin", nil
	}
	u, ok := id.users[uc.Id]
	if !ok {
		return "", auth.InvalidUser(errors.New("i dont know this person"))
	}
	return auth.Scopes(u.Scopes), nil
}

func initMockService(t *testing.T, users []demoUser, duration time.Duration, domain string, pk *ecdsa.PrivateKey) testRouter {
	router := gin.New()
	gin.SetMode(gin.ReleaseMode)

	middleware := auth.NewAuthMiddleware(&pk.PublicKey)
	demoPath := router.Group("/demo")
	demoPath.Use(middleware)

	signer := auth.NewTokenSigner(pk, duration, duration, domain)

	data := map[string]demoUser{}
	for _, u := range users {
		data[u.Name] = u
	}

	inMemory := inMemoryData{data}
	a := auth.DefaultAuthHandler(inMemory.authorizeHumanUser, inMemory.authorizeHumanUser, signer, inMemory.getScopes)
	a.AddAuthProtocol(router, middleware)

	demoPath.GET("/admin", auth.WithScopes(func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{"result": "you are an admin"})
	}, []string{"admin"}))

	demoPath.GET("/action", auth.WithScopes(func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{"result": "you can do the action"})
	}, []string{"action-doer"}))

	router.GET("/not-secured", func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{"result": "everyone can do this"})
	})

	return testRouter{Engine: router, T: t}
}

func TestLogin(t *testing.T) {
	users := []demoUser{demoUser{Name: "tito", Password: "puente", Scopes: "action-doer"}}
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	t.Run("Human user can login", func(t *testing.T) {
		router := initMockService(t, users, time.Hour, "www.myd0main.com", pk)
		resp := router.doLogin("tito", "puente", auth.PasswordCredentials, http.StatusOK)
		authToken, ok := resp["access_token"]
		assert.True(t, ok, "Result must contain an access token")
		assertToken(authToken.(string), pk, t)

		refresh, ok := resp["refresh_token"]
		assert.True(t, ok, "Result must contain an access token")
		assertToken(refresh.(string), pk, t)
	})

	t.Run("Client Credential login", func(t *testing.T) {
		router := initMockService(t, users, time.Hour, "www.myd0main.com", pk)
		resp := router.doLogin("tito", "puente", auth.ClientCredentials, http.StatusOK)
		authToken, ok := resp["access_token"]
		assert.True(t, ok, "Result must contain an access token")
		assertToken(authToken.(string), pk, t)

		refresh, ok := resp["refresh_token"]
		assert.True(t, ok, "Result must contain an access token")
		assertToken(refresh.(string), pk, t)
	})

	t.Run("Login should fail if user is invalid", func(t *testing.T) {
		router := initMockService(t, users, time.Hour, "www.myd0main.com", pk)
		router.doLogin("NOT-TITO", "puente", auth.PasswordCredentials, http.StatusUnauthorized)
	})

	t.Run("Login should fail if password is invalid", func(t *testing.T) {
		router := initMockService(t, users, time.Hour, "www.myd0main.com", pk)
		router.doLogin("tito", "NOT-puente", auth.PasswordCredentials, http.StatusUnauthorized)
	})
}

func TestGetAccessToken(t *testing.T) {
	users := []demoUser{demoUser{Name: "tito", Password: "puente", Scopes: "action-doer"}}
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	t.Run("We should be able to get a new access token with the refresh token", func(t *testing.T) {
		router := initMockService(t, users, time.Hour, "www.myd0main.com", pk)
		resp := router.doLogin("tito", "puente", auth.PasswordCredentials, http.StatusOK)
		accessTkn := resp["access_token"].(string)
		refresh := resp["refresh_token"].(string)

		secondResp := router.doNewAccessToken(refresh, auth.PasswordCredentials, http.StatusOK)
		newAccessTkn := secondResp["access_token"].(string)
		assertToken(newAccessTkn, pk, t)
		assert.NotEqual(t, accessTkn, newAccessTkn)
	})

	t.Run("Same but with client credentials", func(t *testing.T) {
		router := initMockService(t, users, time.Hour, "www.myd0main.com", pk)
		resp := router.doLogin("tito", "puente", auth.ClientCredentials, http.StatusOK)
		accessTkn := resp["access_token"].(string)
		refresh := resp["refresh_token"].(string)

		secondResp := router.doNewAccessToken(refresh, auth.ClientCredentials, http.StatusOK)
		newAccessTkn := secondResp["access_token"].(string)
		assertToken(newAccessTkn, pk, t)
		assert.NotEqual(t, accessTkn, newAccessTkn)
	})

	t.Run("Should fail if we use the access token", func(t *testing.T) {
		router := initMockService(t, users, time.Hour, "www.myd0main.com", pk)
		resp := router.doLogin("tito", "puente", auth.ClientCredentials, http.StatusOK)
		accessTkn := resp["access_token"].(string)
		router.doNewAccessToken(accessTkn, auth.ClientCredentials, http.StatusForbidden)
	})
}

func TestRefreshToken(t *testing.T) {
	users := []demoUser{demoUser{Name: "tito", Password: "puente", Scopes: "action-doer"}}
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	t.Run("We should be able to get new tokens with the refresh token", func(t *testing.T) {
		router := initMockService(t, users, time.Hour, "www.myd0main.com", pk)
		resp := router.doLogin("tito", "puente", auth.PasswordCredentials, http.StatusOK)
		accessTkn := resp["access_token"].(string)
		refresh := resp["refresh_token"].(string)

		secondResp := router.doRefreshToken(refresh, auth.PasswordCredentials, http.StatusOK)
		newAccessTkn := secondResp["access_token"].(string)
		newRefreshTkn := secondResp["refresh_token"].(string)

		assertToken(newAccessTkn, pk, t)
		assertToken(newRefreshTkn, pk, t)

		assert.NotEqual(t, accessTkn, newAccessTkn)
		assert.NotEqual(t, refresh, newRefreshTkn)
	})

	t.Run("Same but with client credentials", func(t *testing.T) {
		router := initMockService(t, users, time.Hour, "www.myd0main.com", pk)
		resp := router.doLogin("tito", "puente", auth.ClientCredentials, http.StatusOK)
		accessTkn := resp["access_token"].(string)
		refresh := resp["refresh_token"].(string)

		secondResp := router.doRefreshToken(refresh, auth.ClientCredentials, http.StatusOK)
		newAccessTkn := secondResp["access_token"].(string)
		newRefreshTkn := secondResp["refresh_token"].(string)

		assertToken(newAccessTkn, pk, t)
		assertToken(newRefreshTkn, pk, t)

		assert.NotEqual(t, accessTkn, newAccessTkn)
		assert.NotEqual(t, refresh, newRefreshTkn)
	})

	t.Run("Should fail if we use the access token", func(t *testing.T) {
		router := initMockService(t, users, time.Hour, "www.myd0main.com", pk)
		resp := router.doLogin("tito", "puente", auth.ClientCredentials, http.StatusOK)
		accessTkn := resp["access_token"].(string)
		router.doNewAccessToken(accessTkn, auth.ClientCredentials, http.StatusForbidden)
	})
}

func TestAccess(t *testing.T) {
	users := []demoUser{demoUser{Name: "tito", Password: "puente", Scopes: "action-doer"}}
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	t.Run("We should access an endpoint if we have the right scopes", func(t *testing.T) {
		router := initMockService(t, users, time.Hour, "www.myd0main.com", pk)
		resp := router.doLogin("tito", "puente", auth.PasswordCredentials, http.StatusOK)
		accessTkn := resp["access_token"].(string)
		router.getActionEndpoint(accessTkn, auth.PasswordCredentials, http.StatusOK)
	})

	t.Run("Same with client credentials", func(t *testing.T) {
		router := initMockService(t, users, time.Hour, "www.myd0main.com", pk)
		resp := router.doLogin("tito", "puente", auth.ClientCredentials, http.StatusOK)
		accessTkn := resp["access_token"].(string)
		router.getAdminEndpoint(accessTkn, auth.ClientCredentials, http.StatusOK)
	})

	t.Run("Deny access based on scopes", func(t *testing.T) {
		router := initMockService(t, users, time.Hour, "www.myd0main.com", pk)
		resp := router.doLogin("tito", "puente", auth.PasswordCredentials, http.StatusOK)
		accessTkn := resp["access_token"].(string)
		router.getAdminEndpoint(accessTkn, auth.PasswordCredentials, http.StatusForbidden)
	})

	t.Run("Reject access if we use refresh token", func(t *testing.T) {
		router := initMockService(t, users, time.Hour, "www.myd0main.com", pk)
		resp := router.doLogin("tito", "puente", auth.PasswordCredentials, http.StatusOK)
		tkn := resp["refresh_token"].(string)
		router.getAdminEndpoint(tkn, auth.PasswordCredentials, http.StatusForbidden)
	})

	t.Run("Reject expired token", func(t *testing.T) {
		router := initMockService(t, users, time.Nanosecond, "www.myd0main.com", pk)
		resp := router.doLogin("tito", "puente", auth.PasswordCredentials, http.StatusOK)
		time.Sleep(time.Second)
		tkn := resp["access_token"].(string)
		router.getAdminEndpoint(tkn, auth.PasswordCredentials, http.StatusUnauthorized)
	})

	t.Run("Reject tokens from an unkown source", func(t *testing.T) {
		router := initMockService(t, users, time.Hour, "www.myd0main.com", pk)
		otherPk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		signer := auth.NewTokenSigner(otherPk, time.Hour, time.Hour, "www.myd0main.com")

		tkn, err := signer.GetAccessToken("tito", "action-doer", auth.PasswordCredentials)
		require.NoError(t, err)

		router.getAdminEndpoint(tkn, auth.PasswordCredentials, http.StatusUnauthorized)
	})

	t.Run("Reject request if no token is present", func(t *testing.T) {
		router := initMockService(t, users, time.Hour, "www.myd0main.com", pk)
		req, err := http.NewRequest("GET", "/demo/admin", nil)
		require.NoError(router.T, err)
		router.runRequest(req, http.StatusUnauthorized)
	})

	t.Run("Allow to hit not protected endpoints", func(t *testing.T) {
		router := initMockService(t, users, time.Hour, "www.myd0main.com", pk)
		req, err := http.NewRequest("GET", "/not-secured", nil)
		require.NoError(router.T, err)
		router.runRequest(req, http.StatusOK)
	})
}

func (router testRouter) doLogin(user string, pass string, grant string, expectedStatus int) map[string]interface{} {
	body := `{}`
	url := "/login"
	req, err := http.NewRequest("POST", url, strings.NewReader(body))
	require.NoError(router.T, err)

	a := fmt.Sprintf("%s:%s", user, pass)
	b := []byte(a)
	creds := base64.StdEncoding.EncodeToString(b)

	req.Header.Set(auth.AuthorizationHeader, fmt.Sprintf("basic %s", creds))
	req.Header.Set(auth.GrantTypeHeader, grant)

	code, response := router.runRequest(req, expectedStatus)
	assert.Equal(router.T, code, expectedStatus)
	return response
}

func (router testRouter) getAdminEndpoint(accessToken string, grant string, expectedStatus int) {
	router.doAuthGet(accessToken, grant, expectedStatus, "/demo/admin")
}

func (router testRouter) getActionEndpoint(accessToken string, grant string, expectedStatus int) {
	router.doAuthGet(accessToken, grant, expectedStatus, "/demo/action")
}

func (router testRouter) doNewAccessToken(refresh string, grant string, expectedStatus int) map[string]interface{} {
	return router.doAuthGet(refresh, grant, expectedStatus, "/refresh")
}

func (router testRouter) doRefreshToken(refresh string, grant string, expectedStatus int) map[string]interface{} {
	return router.doAuthGet(refresh, grant, expectedStatus, "/token")
}

func (router testRouter) doAuthGet(token string, grant string, expectedStatus int, url string) map[string]interface{} {
	req, err := http.NewRequest("GET", url, nil)
	require.NoError(router.T, err)

	req.Header.Set(auth.AuthorizationHeader, fmt.Sprintf("bearer %s", token))
	req.Header.Set(auth.GrantTypeHeader, grant)

	code, response := router.runRequest(req, expectedStatus)
	assert.Equal(router.T, code, expectedStatus)
	return response
}

func (router testRouter) runRequest(req *http.Request, expectedStatus int) (int, map[string]interface{}) {
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(router.T, expectedStatus, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(router.T, err)

	return w.Code, response
}

func assertToken(token string, pk *ecdsa.PrivateKey, t *testing.T) {
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("worng signing method")
		}
		return &pk.PublicKey, nil
	})
	//TODO: assert the claims...
	require.NoError(t, err)
}
