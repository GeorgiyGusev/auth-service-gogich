package internal

import (
	"errors"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"golang.org/x/crypto/bcrypt"
)

type Handler struct {
	identityRepo IdentityRepo
	validator    *validator.Validate
}

func (h *Handler) createIdentity(ctx *fiber.Ctx) error {
	var req CreateIdentityRequest

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

	resp, err := h.identityRepo.CreateIdentity(
		ctx.Context(),
		req.Identity,
		req.IdentityType,
		string(password_hash),
		"bcrypt",
	)
	if err != nil {
		var uniqueError *UniqueConstraintError
		if errors.As(err, &uniqueError) {
			return ctx.Status(fiber.StatusConflict).JSON(fiber.Map{
				"details": uniqueError.Error(),
			})
		}

		return ctx.SendStatus(500)
	}

	return ctx.JSON(resp)
}

// TODO: Create login endpoint
// TODO: Create logout endpoint

func NewHandler(identityRepo IdentityRepo) *Handler {
	return &Handler{
		validator:    validator.New(),
		identityRepo: identityRepo,
	}
}

func (h *Handler) RegisterHandler(server *fiber.App) {
	identityGroup := server.Group("/identity")
	{
		identityGroup.Post("/sign-up", h.createIdentity)
	}
}
