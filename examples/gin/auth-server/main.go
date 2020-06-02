package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"github.com/bryst/windmill/pkg/auth"
	"github.com/gin-gonic/gin"
	"log"
	"time"
)

func main() {

	router := gin.New()
	api := router.Group("/api")
	v1 := api.Group("/v1")

	localImplementations := initMockData()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	ginAuth, err := auth.BasicGinAuth(&auth.GinAuthConfig{
		UsrAuthorizer:      localImplementations.authorize,
		ClientAuthorizer:   localImplementations.authorize, //Potentially this could have other logic
		ScopeProvider:      localImplementations.getScopes,
		AudValidator:       localImplementations.validateAudience,
		ClaimProvider:      localImplementations.getClaims,
		SigningKey:         key,
		AccessTknDuration:  time.Hour,
		RefreshTknDuration: time.Hour * 24,
		AppID:              "AUTH:SERVER"})

	if err != nil {
		log.Fatal(err)
	}

	ginAuth.AddAuthProtocol(v1, auth.NewAuthServerMiddleware())

	if err := router.Run("0.0.0.0:8080"); err != nil {
		log.Fatal(err)
	}
}

// MOCK IMPLEMENTATION
func initMockData() mockImplementation {
	userRepo := map[string]string{"user1": "pwd1233", "user2": "pwd1234", "user3": "pwd1234"}

	userScopes := map[string]map[string]bool{
		"user1": {"read:api": true},
		"user2": {"read:api": true, "admin": true},
		"user3": {"read:api": true, "admin": true}}

	clientRegistry := map[string][]string{
		"user1": {"API1", "API2"},
		"user2": {"API1", "API3"},
		"user3": {"API3"},
	}

	claimRepo := map[string]string{"API2": "custom"}

	return mockImplementation{
		userRepo:       userRepo,
		userScopes:     userScopes,
		clientRegistry: clientRegistry,
		claimRepo:      claimRepo,
	}

}

type mockImplementation struct {
	userRepo       map[string]string
	userScopes     map[string]map[string]bool
	clientRegistry map[string][]string
	claimRepo      map[string]string
}

func (dh mockImplementation) authorize(uc auth.Credentials) error {
	pwd, ok := dh.userRepo[uc.ID]
	if !ok {
		return auth.InvalidUser(errors.New("unknown user"))
	}
	if pwd != uc.Password {
		return auth.InvalidUser(errors.New("unknown user"))
	}
	return nil
}

func (dh mockImplementation) getScopes(userID string, grant string, aud string, requested auth.Scopes) (auth.Scopes, error) {
	// you could also have different scopes for the same user for different  resources,
	// or give different scopes depending the grant type.
	// Since this is a mock version, we are ignoring those fields
	scopes, ok := dh.userScopes[userID]
	if !ok {
		return nil, auth.InvalidUser(errors.New("unknown user"))
	}
	ret := []string{}
	for _, s := range requested {
		if _, granted := scopes[s]; granted {
			ret = append(ret, s)
		}
	}
	return ret, nil
}

func (dh mockImplementation) getClaims(identifier string, aud string) ([]auth.Claim, error) {
	apps := dh.clientRegistry[identifier]
	for _, aID := range apps {
		if aID == aud {
			claim, ok := dh.claimRepo[aID]
			if ok {
				return []auth.Claim{{Key: claim, Value: "custom-claim"}}, nil
			}
		}
	}
	return nil, nil
}

func (dh mockImplementation) validateAudience(userID string, _ string, aud string) (bool, error) {
	if "" == aud {
		return true, nil
	}
	apps := dh.clientRegistry[userID]
	for _, aID := range apps {
		if aID == aud {
			return true, nil
		}
	}
	return false, nil
}
