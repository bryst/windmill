package auth

type Scopes string

type UserCredentials struct {
	Id       string
	Password string
	Grant    string
}

const PasswordCredentials = "password_credentials"
const ClientCredentials = "client_credentials"

const GrantTypeHeader = "GRANT_TYPE"
const AuthorizationHeader = "Authorization"

type Authorizer func(uc UserCredentials) error

type ScopeProvider func(uc UserCredentials) (Scopes, error)
