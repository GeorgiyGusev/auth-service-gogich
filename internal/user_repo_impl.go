package internal

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jmoiron/sqlx"
)

type UserRepoImpl struct {
	db *sqlx.DB
}

func NewUserRepoImpl(db *sqlx.DB) *UserRepoImpl {
	return &UserRepoImpl{
		db,
	}
}
func (r *UserRepoImpl) CreateUser(
	ctx context.Context,
	email string,
	passwordHash string,
) (*CreateUserResponse, error) {
	const query = `
	INSERT INTO identities.users(email, password_hash)
	VALUES ($1, $2) 
	RETURNING id, email
	`
	var result CreateUserResponse
	if err := r.db.GetContext(ctx, &result, query, email, passwordHash); err != nil {
		if IsUniqueConstraintError(err) {
			return nil, &UniqueConstraintError{
				Err:     err,
				Message: "user already exists",
			}
		}
		return nil, err
	}
	return &result, nil
}

func (r *UserRepoImpl) GetUserById(
	ctx context.Context,
	id string,
) (*User, error) {
	const query = `
	SELECT id, email, password_hash, created_at, updated_at 
	FROM identities.users 
	WHERE id = $1
	LIMIT 1
	`
	var result User
	if err := r.db.GetContext(ctx, &result, query, id); err != nil {
		return nil, err
	}
	return &result, nil
}

func (r *UserRepoImpl) GetUserByEmail(
	ctx context.Context,
	email string,
) (*User, error) {
	const query = `
	SELECT id, email, password_hash, created_at, updated_at 
	FROM identities.users 
	WHERE email = $1
	LIMIT 1
	`
	var result User
	if err := r.db.GetContext(ctx, &result, query, email); err != nil {
		return nil, err
	}
	return &result, nil
}

// UniqueConstraintError кастомная ошибка для нарушения уникальности
type UniqueConstraintError struct {
	Message string
	Err     error
}

func (e *UniqueConstraintError) Error() string {
	return fmt.Sprintf("%s : %s", e.Err.Error(), e.Message)
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
