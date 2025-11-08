package internal

import (
	"context"
)

type UserRepo interface {
	CreateUser(ctx context.Context, email string, passwordHash string) (*CreateUserResponse, error)
	GetUserById(ctx context.Context, id string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
}

type SessionRepository interface {
	SaveSession(ctx context.Context, session *Session) error
	GetSession(ctx context.Context, sessionID string) (*Session, error)
	BlockSession(ctx context.Context, sessionID string) error
	DeleteSession(ctx context.Context, sessionID string) error
	GetUserSessions(ctx context.Context, userID string) ([]*Session, error)
	BlockAllUserSessions(ctx context.Context, userID string) error
	CleanupExpiredSessions(ctx context.Context) error
}
