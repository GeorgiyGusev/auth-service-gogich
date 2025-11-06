package internal

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jmoiron/sqlx"
)

type IdentityRepoImpl struct {
	db *sqlx.DB
}

func NewIdentityRepoImpl(db *sqlx.DB) *IdentityRepoImpl {
	return &IdentityRepoImpl{
		db,
	}
}
func (r *IdentityRepoImpl) CreateIdentity(
	ctx context.Context,
	identity string,
	identityType string,
	passwordHash string,
	hashType string,
) (*CreateIdentityResponse, error) {
	const query = `
	INSERT INTO identities.identities(identity, identity_type, password_hash, hash_type)
	VALUES ($1, $2, $3, $4) 
	RETURNING id, identity
	`
	var result CreateIdentityResponse
	if err := r.db.GetContext(ctx, &result, query, identity, identityType, passwordHash, hashType); err != nil {
		if IsUniqueConstraintError(err) {
			return nil, &UniqueConstraintError{
				Field:   "identity",
				Message: "identity already exists",
			}
		}
		return nil, err
	}
	return &result, nil
}

func (r *IdentityRepoImpl) GetIdentityById(
	ctx context.Context,
	id string,
) (*Identity, error) {
	const query = `
	SELECT id, identity, identity_type, password_hash, hash_type, created_at, updated_at 
	FROM identities.identities 
	WHERE id = $1
	LIMIT 1
	`
	var result Identity
	if err := r.db.GetContext(ctx, &result, query, id); err != nil {
		return nil, err
	}
	return &result, nil
}

func (r *IdentityRepoImpl) GetIdentity(
	ctx context.Context,
	identity string,
) (*Identity, error) {
	const query = `
	SELECT id, identity, identity_type, password_hash, hash_type, created_at, updated_at 
	FROM identities.identities 
	WHERE identity = $1
	LIMIT 1
	`
	var result Identity
	if err := r.db.GetContext(ctx, &result, query, identity); err != nil {
		return nil, err
	}
	return &result, nil
}

// UniqueConstraintError кастомная ошибка для нарушения уникальности
type UniqueConstraintError struct {
	Field   string
	Message string
}

func (e *UniqueConstraintError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

// IsUniqueConstraintError проверяет нарушение уникальности
func IsUniqueConstraintError(err error) bool {
	if err == nil {
		return false
	}

	// Пробуем привести к pgconn.PgError (если используем pgx)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505" // unique_violation
	}

	// Универсальная проверка по тексту
	errorMsg := strings.ToLower(err.Error())
	return strings.Contains(errorMsg, "23505") ||
		strings.Contains(errorMsg, "unique constraint") ||
		strings.Contains(errorMsg, "duplicate key value")
}
