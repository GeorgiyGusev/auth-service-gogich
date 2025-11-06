package internal

import "context"

type IdentityRepo interface {
	CreateIdentity(ctx context.Context, identity string, identityType string, passwordHash string, hashType string) (*CreateIdentityResponse, error)
	GetIdentityById(ctx context.Context, id string) (*Identity, error)
	GetIdentity(ctx context.Context, identity string) (*Identity, error)
}
