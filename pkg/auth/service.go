package auth

import (
	"errors"
)

type authorizationService struct {
	authorizers map[string]Authorizer
	signer      TokenSigner
	scopes      ScopeProvider
}

type ServiceCredentials struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func (as authorizationService) Authorize(credentials UserCredentials) (*ServiceCredentials, error) {
	authorizer, ok := as.authorizers[credentials.Grant]
	if !ok {
		return nil, InvalidGrant(errors.New("invalid grant type"))
	}

	err := authorizer(credentials)
	if err != nil {
		return nil, err
	}

	scopes, err := as.scopes(credentials)
	if err != nil {
		return nil, err
	}

	return as.createCredentials(credentials.Id, scopes, credentials.Grant)
}

func (as authorizationService) Refresh(credentials UserCredentials) (*ServiceCredentials, error) {
	scopes, err := as.scopes(credentials)
	if err != nil {
		return nil, err
	}

	return as.createCredentials(credentials.Id, scopes, credentials.Grant)
}

func (as authorizationService) AccessToken(credentials UserCredentials) (string, error) {
	scopes, err := as.scopes(credentials)
	if err != nil {
		return "", err
	}

	return as.signer.GetAccessToken(credentials.Id, scopes, credentials.Grant)
}

func (as *authorizationService) createCredentials(senderId string, scopes Scopes, grantType string) (*ServiceCredentials, error) {
	accessToken, err := as.signer.GetAccessToken(senderId, scopes, grantType)
	if err != nil {
		return nil, err
	}

	refreshToken, err := as.signer.GetRefreshToken(senderId, grantType)
	if err != nil {
		return nil, err
	}

	return &ServiceCredentials{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}
