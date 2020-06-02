package auth

// InvalidGrant indicates an error with the grant type
type InvalidGrant error

// InvalidUser indicates an error for the user authentication
type InvalidUser error

// Unexpected errors that are not expected
type Unexpected error

// UnknownAudience indicates an error related with the audience requested
type UnknownAudience error

// InvalidToken indicates that the jwt is not valid.
type InvalidToken error
