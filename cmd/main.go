package main

import (
	"log"
	"log/slog"
	"os"

	"github.com/KontoraMarketel/auth-service-gogich/internal"
	"github.com/KontoraMarketel/auth-service-gogich/internal/clients"
	"github.com/KontoraMarketel/auth-service-gogich/internal/conns"
	"github.com/KontoraMarketel/auth-service-gogich/internal/docs"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/joho/godotenv"
	slogfiber "github.com/samber/slog-fiber"
)

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

	docs.NewHandler().Register(baseGroup)

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

	log.Fatal(app.Listen(":3000"))
}
