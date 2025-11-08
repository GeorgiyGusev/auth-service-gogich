package internal

import "time"

// CreateUserRequest представляет запрос на создание пользователя
// swagger:model CreateUserRequest
type CreateUserRequest struct {
	Email    string `json:"email" validate:"required,email" example:"user@example.com"`
	Password string `json:"password" validate:"required,min=8,max=100" example:"strongpassword123"`
}

// CreateUserResponse представляет ответ при создании пользователя
// swagger:model CreateUserResponse
type CreateUserResponse struct {
	ID       string `json:"id" db:"id" example:"550e8400-e29b-41d4-a716-446655440000"`
	Identity string `json:"email" db:"email" example:"user@example.com"`
}

// User представляет модель пользователя
type User struct {
	ID           string    `db:"id"`
	Email        string    `db:"email"`
	PasswordHash string    `db:"password_hash"`
	CreatedAt    time.Time `db:"created_at"`
	UpdatedAt    time.Time `db:"updated_at"`
}

// LoginRequest представляет запрос на аутентификацию
// swagger:model LoginRequest
type LoginRequest struct {
	Email    string `json:"email" validate:"required,email" example:"user@example.com"`
	Password string `json:"password" validate:"required,min=8" example:"strongpassword123"`
}

// LoginResponse представляет ответ с токенами аутентификации
// swagger:model LoginResponse
type LoginResponse struct {
	AccessToken  string `json:"access_token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
	RefreshToken string `json:"refresh_token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
	TokenType    string `json:"token_type" example:"Bearer"`
	ExpiresIn    int    `json:"expires_in" example:"900"`
}

const (
	AccessTokenTyp  = "access"
	RefreshTokenTyp = "refresh"
)

// AccessToken представляет структуру access токена
type AccessToken struct {
	Subject   string `json:"sub"`
	SessionID string `json:"sid"`
	ExpiresAt int64  `json:"exp"`
	Type      string `json:"typ"`
	IssuedAt  int64  `json:"iat"`
}

// RefreshToken представляет структуру refresh токена
type RefreshToken struct {
	ExpiresAt int64  `json:"exp"`
	SessionID string `json:"sid"`
	Type      string `json:"typ"`
	IssuedAt  int64  `json:"iat"`
}

// Session представляет модель сессии пользователя
type Session struct {
	SessionID    string    `json:"session_id"`
	UserID       string    `json:"user_id"`
	RefreshToken string    `json:"refresh_token"`
	UserAgent    string    `json:"user_agent"`
	IPAddress    string    `json:"ip_address"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	IsBlocked    bool      `json:"is_blocked"`
}

// RefreshRequest представляет запрос на обновление токенов
// swagger:model RefreshRequest
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
}

// RefreshResponse представляет ответ с обновленными токенами
// swagger:model RefreshResponse
type RefreshResponse struct {
	AccessToken  string `json:"access_token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
	RefreshToken string `json:"refresh_token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
	TokenType    string `json:"token_type" example:"Bearer"`
	ExpiresIn    int    `json:"expires_in" example:"900"`
}

// LogoutRequest представляет запрос на выход из системы
// swagger:model LogoutRequest
type LogoutRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
}

// ErrorResponse представляет стандартный ответ об ошибке
// swagger:model ErrorResponse
type ErrorResponse struct {
	Error   string `json:"error" example:"Validation failed"`
	Details string `json:"details,omitempty" example:"Email is required"`
}

// MessageResponse представляет стандартный ответ с сообщением
// swagger:model MessageResponse
type MessageResponse struct {
	Message string `json:"message" example:"Successfully logged out"`
}
