package internal

import (
	"errors"
	"time"

	"github.com/KontoraMarketel/auth-service-gogich/internal/clients"
	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// Handler представляет обработчик HTTP запросов
type Handler struct {
	userRepo    UserRepo
	sessionRepo SessionRepository

	validator           *validator.Validate
	cryptoServiceClient *clients.CryptoServiceClient
}

// NewHandler создает новый экземпляр Handler
func NewHandler(userRepo UserRepo, cryptoServiceClient *clients.CryptoServiceClient, sessionsRepo SessionRepository) *Handler {
	return &Handler{
		validator:           validator.New(),
		userRepo:            userRepo,
		cryptoServiceClient: cryptoServiceClient,
		sessionRepo:         sessionsRepo,
	}
}

// CreateUser godoc
// @Summary Регистрация нового пользователя
// @Description Создает нового пользователя в системе
// @Tags identity
// @Accept json
// @Produce json
// @Param request body CreateUserRequest true "Данные для регистрации"
// @Success 201 {object} CreateUserResponse
// @Failure 400 {object} ErrorResponse
// @Failure 409 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /identity/sign-up [post]
func (h *Handler) createUser(ctx *fiber.Ctx) error {
	var req CreateUserRequest

	if err := ctx.BodyParser(&req); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Invalid request body",
			"details": err.Error(),
		})
	}

	if err := h.validator.StructCtx(ctx.Context(), &req); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Validation failed",
			"details": err.Error(),
		})
	}

	password_hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return ctx.SendStatus(fiber.StatusInternalServerError)
	}

	resp, err := h.userRepo.CreateUser(
		ctx.Context(),
		req.Email,
		string(password_hash),
	)
	if err != nil {
		var uniqueError *UniqueConstraintError
		if errors.As(err, &uniqueError) {
			return ctx.Status(fiber.StatusConflict).JSON(fiber.Map{
				"details": uniqueError.Error(),
			})
		}

		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err,
		})
	}

	return ctx.Status(fiber.StatusCreated).JSON(resp)
}

// Login godoc
// @Summary Аутентификация пользователя
// @Description Выполняет вход пользователя и возвращает токены доступа
// @Tags identity
// @Accept json
// @Produce json
// @Param request body LoginRequest true "Данные для входа"
// @Success 200 {object} LoginResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /identity/sign-in [post]
func (h *Handler) login(ctx *fiber.Ctx) error {
	var req LoginRequest

	if err := ctx.BodyParser(&req); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Invalid request body",
			"details": err.Error(),
		})
	}

	if err := h.validator.StructCtx(ctx.Context(), &req); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Validation failed",
			"details": err.Error(),
		})
	}

	user, err := h.userRepo.GetUserByEmail(ctx.Context(), req.Email)
	if err != nil {
		return ctx.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error":   "User not found",
			"details": err.Error(),
		})
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Incorrect email or password",
		})
	}

	// 🔑 Генерируем session_id
	sessionID := uuid.NewString()

	// 🎫 Создаем токены со встроенным session_id
	accessToken := &AccessToken{
		Subject:   user.ID,
		SessionID: sessionID, // ← Добавляем session_id в токен
		ExpiresAt: time.Now().Add(15 * time.Minute).Unix(),
		Type:      AccessTokenTyp,
		IssuedAt:  time.Now().Unix(),
	}

	refreshToken := &RefreshToken{
		SessionID: sessionID, // ← Добавляем session_id в токен
		ExpiresAt: time.Now().Add(24 * 30 * time.Hour).Unix(),
		Type:      RefreshTokenTyp,
		IssuedAt:  time.Now().Unix(),
	}

	accessTokenString, err := h.cryptoServiceClient.Sign(accessToken)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "cannot sign access token",
			"details": err.Error(),
		})
	}

	refreshTokenString, err := h.cryptoServiceClient.Sign(refreshToken)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "cannot sign refresh token",
			"details": err.Error(),
		})
	}

	// 💾 Сохраняем сессию в Redis
	session := &Session{
		SessionID:    sessionID,
		UserID:       user.ID,
		RefreshToken: refreshTokenString, // Сохраняем подписанный refresh token
		UserAgent:    ctx.Get("User-Agent"),
		IPAddress:    ctx.IP(),
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(24 * 30 * time.Hour), // 30 дней
		IsBlocked:    false,
	}

	if err := h.sessionRepo.SaveSession(ctx.Context(), session); err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "cannot create session",
			"details": err.Error(),
		})
	}

	// ✅ Возвращаем токены (session_id теперь внутри токенов)
	return ctx.JSON(&LoginResponse{
		AccessToken:  accessTokenString,
		RefreshToken: refreshTokenString,
		TokenType:    "Bearer",
		ExpiresIn:    900, // 15 минут в секундах
	})
}

// Refresh godoc
// @Summary Обновление токенов
// @Description Обновляет access и refresh токены с использованием валидного refresh токена
// @Tags identity
// @Accept json
// @Produce json
// @Param request body RefreshRequest true "Refresh token"
// @Success 200 {object} RefreshResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /identity/refresh [post]
func (h *Handler) refresh(ctx *fiber.Ctx) error {
	var req RefreshRequest

	if err := ctx.BodyParser(&req); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Invalid request body",
			"details": err.Error(),
		})
	}

	if err := h.validator.StructCtx(ctx.Context(), &req); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Validation failed",
			"details": err.Error(),
		})
	}

	// 🔐 Валидируем refresh token и извлекаем payload
	refreshToken, err := h.cryptoServiceClient.Verify(req.RefreshToken)
	if err != nil {
		return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Invalid refresh token",
		})
	}

	claims, ok := refreshToken.Claims.(jwt.MapClaims)
	if !ok {
		return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Invalid or expired token",
		})
	}

	tokenType, ok := claims["typ"].(string)
	if !ok {
		return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Invalid or expired token",
		})
	}

	// 📋 Проверяем тип токена
	if tokenType != RefreshTokenTyp {
		return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Not a refresh token",
		})
	}

	expire, ok := claims["exp"].(float64)
	if !ok {
		return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Invalid or expired token",
		})
	}
	// ⏰ Проверяем срок действия
	if time.Now().Unix() > int64(expire) {
		return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Refresh token expired",
		})
	}

	sessionID, ok := claims["sid"].(string)
	if !ok {
		return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Invalid or expired token",
		})
	}
	if sessionID == "" {
		return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Missing session ID in token",
		})
	}

	// 🔍 Получаем сессию из Redis
	session, err := h.sessionRepo.GetSession(ctx.Context(), sessionID)
	if err != nil {
		return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Session not found",
		})
	}

	// 🚫 Проверяем блокировку сессии
	if session.IsBlocked {
		return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Session is blocked",
		})
	}

	// 🔄 Проверяем совпадение refresh token (защита от повтора)
	if session.RefreshToken != req.RefreshToken {
		// Возможная атака! Блокируем сессию
		h.sessionRepo.BlockSession(ctx.Context(), sessionID)
		return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Token mismatch",
		})
	}

	// 👤 Получаем данные пользователя
	user, err := h.userRepo.GetUserById(ctx.Context(), session.UserID)
	if err != nil {
		return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "User not found",
		})
	}

	// 🎫 Генерируем НОВУЮ пару токенов с ТЕМ ЖЕ session_id
	newAccessToken := &AccessToken{
		Subject:   user.ID,
		SessionID: sessionID,
		ExpiresAt: time.Now().Add(15 * time.Minute).Unix(),
		Type:      AccessTokenTyp,
		IssuedAt:  time.Now().Unix(),
	}

	newRefreshToken := &RefreshToken{
		SessionID: sessionID,
		ExpiresAt: time.Now().Add(24 * 30 * time.Hour).Unix(),
		Type:      RefreshTokenTyp,
		IssuedAt:  time.Now().Unix(),
	}

	newAccessTokenString, err := h.cryptoServiceClient.Sign(newAccessToken)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Cannot sign access token",
		})
	}

	newRefreshTokenString, err := h.cryptoServiceClient.Sign(newRefreshToken)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Cannot sign refresh token",
		})
	}

	// 💾 Обновляем сессию с НОВЫМ refresh token
	session.RefreshToken = newRefreshTokenString
	session.ExpiresAt = time.Now().Add(24 * 30 * time.Hour)

	if err := h.sessionRepo.SaveSession(ctx.Context(), session); err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Cannot update session",
		})
	}

	// ✅ Возвращаем новые токены
	return ctx.JSON(&RefreshResponse{
		AccessToken:  newAccessTokenString,
		RefreshToken: newRefreshTokenString,
		TokenType:    "Bearer",
		ExpiresIn:    900,
	})
}

// Logout godoc
// @Summary Выход из системы
// @Description Выполняет выход пользователя и блокирует сессию
// @Tags identity
// @Accept json
// @Produce json
// @Param request body LogoutRequest true "Refresh token для выхода"
// @Success 200 {object} MessageResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /identity/logout [post]
func (h *Handler) logout(ctx *fiber.Ctx) error {
	var req LogoutRequest

	if err := ctx.BodyParser(&req); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Invalid request body",
			"details": err.Error(),
		})
	}

	if err := h.validator.StructCtx(ctx.Context(), &req); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Validation failed",
			"details": err.Error(),
		})
	}

	// 🔐 Валидируем refresh token и извлекаем claims
	refreshToken, err := h.cryptoServiceClient.Verify(req.RefreshToken)
	if err != nil {
		return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Invalid refresh token",
		})
	}

	claims, ok := refreshToken.Claims.(jwt.MapClaims)
	if !ok {
		return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Invalid token claims",
		})
	}

	// 📋 Проверяем тип токена
	tokenType, ok := claims["typ"].(string)
	if !ok || tokenType != RefreshTokenTyp {
		return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Not a refresh token",
		})
	}

	// 🗄️ Получаем session_id из claims
	sessionID, ok := claims["sid"].(string)
	if !ok || sessionID == "" {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Missing session ID in token",
		})
	}

	// 🔍 Получаем сессию из Redis для дополнительной проверки
	session, err := h.sessionRepo.GetSession(ctx.Context(), sessionID)
	if err != nil {
		// Если сессия не найдена, все равно возвращаем успех
		// (возможно уже была удалена/заблокирована)
		return ctx.JSON(fiber.Map{
			"message": "Successfully logged out",
		})
	}

	// 🔄 Проверяем совпадение refresh token (дополнительная безопасность)
	if session.RefreshToken != req.RefreshToken {
		// Возможная атака! Блокируем сессию
		h.sessionRepo.BlockSession(ctx.Context(), sessionID)
		return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Token mismatch",
		})
	}

	// 🚫 Блокируем сессию в Redis
	if err := h.sessionRepo.BlockSession(ctx.Context(), sessionID); err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Cannot logout",
		})
	}

	return ctx.JSON(fiber.Map{
		"message": "Successfully logged out",
	})
}

// RegisterHandler регистрирует обработчики маршрутов
func (h *Handler) RegisterHandler(server fiber.Router) {
	identityGroup := server.Group("/identity")
	{
		identityGroup.Post("/sign-up", h.createUser)
		identityGroup.Post("/sign-in", h.login)
		identityGroup.Post("/refresh", h.refresh)
		identityGroup.Post("/logout", h.logout)
	}
}
