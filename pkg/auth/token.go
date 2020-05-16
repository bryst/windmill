package auth

import (
	"crypto/ecdsa"
	"github.com/dgrijalva/jwt-go"
	"time"
)

type tokenClaims struct {
	UserId    string
	Scopes    Scopes
	Exp       time.Duration
	GrantType string
}

type TokenSigner interface {
	GetAccessToken(userId string, scopes Scopes, grantType string) (string, error)
	GetRefreshToken(userId string, grantType string) (string, error)
}

func NewTokenSigner(pkey *ecdsa.PrivateKey, atd time.Duration, rtd time.Duration, d string) TokenSigner {
	return &tokenSigner{
		privateKey:           pkey,
		accessTokenDuration:  atd,
		refreshTokenDuration: rtd,
		domain:               d,
	}
}

type tokenSigner struct {
	privateKey           *ecdsa.PrivateKey
	accessTokenDuration  time.Duration
	refreshTokenDuration time.Duration
	domain               string
}

const RefreshTokenScope = "auth/refresh"

func (ts *tokenSigner) GetAccessToken(userId string, scopes Scopes, grantType string) (string, error) {
	return ts.signToken(&tokenClaims{
		UserId:    userId,
		Scopes:    scopes,
		Exp:       ts.accessTokenDuration,
		GrantType: grantType,
	})
}

func (ts *tokenSigner) GetRefreshToken(userId string, grantType string) (string, error) {
	return ts.signToken(&tokenClaims{
		UserId:    userId,
		Scopes:    RefreshTokenScope,
		Exp:       ts.refreshTokenDuration,
		GrantType: grantType,
	})
}

func (ts *tokenSigner) signToken(claims *tokenClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"scopes":     claims.Scopes,
		"sub":        claims.UserId,
		"aud":        ts.domain,
		"iss":        ts.domain,
		"exp":        time.Now().Add(claims.Exp).Unix(),
		"grant_type": claims.GrantType,
	})
	ret, err := token.SignedString(ts.privateKey)
	return ret, err
}
