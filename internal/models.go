package internal

import "time"

type CreateIdentityRequest struct {
	Identity     string `json:"identity" validate:"required,email"`
	IdentityType string `json:"identity_type" validate:"required,oneof=email"`
	Password     string `json:"password" validate:"required,min=8,max=100"`
}

type CreateIdentityResponse struct {
	ID       string `json:"id" db:"id"`
	Identity string `json:"identity" db:"identity"`
}

type Identity struct {
	ID           string    `db:"id"`
	Identity     string    `db:"identity"`
	IdentityType string    `db:"identity_type"`
	PasswordHash string    `db:"password_hash"`
	HashType     string    `db:"hash_type"`
	CreatedAt    time.Time `db:"created_at"`
	UpdatedAt    time.Time `db:"updated_at"`
}
