package main

import (
	"log"
	"log/slog"
	"os"

	_ "github.com/KontoraMarketel/auth-service-gogich/docs"
	"github.com/KontoraMarketel/auth-service-gogich/internal"
	"github.com/KontoraMarketel/auth-service-gogich/internal/clients"
	"github.com/KontoraMarketel/auth-service-gogich/internal/conns"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/joho/godotenv"
	slogfiber "github.com/samber/slog-fiber"
	fiberSwagger "github.com/swaggo/fiber-swagger"
)

// @BasePath  /auth/api/v1
func main() {
	err := godotenv.Load()

	l := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	slog.SetDefault(l)

	app := fiber.New()
	app.Use(slogfiber.New(l))
	app.Use(cors.New(cors.Config{
		AllowOrigins: "*",
		AllowHeaders: "*",
		AllowMethods: "*",
	}))
	baseGroup := app.Group("/auth/api/v1")

	postgresConn, err := conns.NewPostgresConn()
	if err != nil {
		log.Fatal(err)
	}

	redisClient, err := conns.NewRedisConn()
	if err != nil {
		log.Fatal(err)
	}

	sessionsRepo := internal.NewSessionRepository(redisClient)

	cryptoServiceClient, err := clients.NewCryptoServiceClient()
	if err != nil {
		log.Fatal(err)
	}

	userRepoImpl := internal.NewUserRepoImpl(postgresConn)
	internal.NewHandler(userRepoImpl, cryptoServiceClient, sessionsRepo).RegisterHandler(baseGroup)

	baseGroup.Get("/swagger/*", fiberSwagger.WrapHandler)

	log.Fatal(app.Listen(":3000"))
}
